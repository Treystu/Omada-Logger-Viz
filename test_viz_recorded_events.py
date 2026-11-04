"""Local API tests for searchable recorded event history."""

import json
import os
import socket
import tempfile
import threading
import unittest
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

import omada_event_store as store
import omada_viz as viz


class RecordedEventRouteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.raw_path = os.path.join(self.tmp.name, "firewall.log")
        self.db_path = store.default_event_path(self.raw_path)
        with open(self.raw_path, "w", encoding="utf-8"):
            pass
        self.db = store.EventStore(self.db_path, self.raw_path, 8 * 1024 * 1024)
        self.db.add("2026-11-03T10:00:00-10:00", "192.0.2.10", [
            b"<134>DHCP Server allocated IP address 192.168.1.20 for the [client:aa:bb:cc:dd:ee:01]",
            b"<134>[client:aa:bb:cc:dd:ee:02] is roaming from [ap:aa:aa:aa:aa:aa] to [ap:bb:bb:bb:bb:bb].",
            b"<134>opaque original record",
        ])
        self.db.add("2026-11-03T10:01:00-10:00", "192.0.2.11", [
            b"<134>DHCP Server allocated IP address 192.168.1.21 for the [client:aa:bb:cc:dd:ee:03]",
        ])
        self.db.add("2026-11-03T10:02:00-10:00", None, [b"orphan record without a sender envelope"])
        self.db.close()
        self.server = viz.VizServer(("127.0.0.1", 0), viz.Handler)
        self.server.args = SimpleNamespace(log_file=self.raw_path, event_file=self.db_path,
                                            html_dir=self.tmp.name, raw_tail=10,
                                            condense_file=os.path.join(self.tmp.name, "condensed.json"),
                                            recovery_status_file=os.path.join(self.tmp.name, "recovery.json"))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.socket.getsockname()[1]
        self.opener = build_opener(ProxyHandler({}))

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=3)
        self.server.server_close()
        self.tmp.cleanup()

    def get(self, query=""):
        url = "http://127.0.0.1:%d/api/recorded-events" % self.port
        if query:
            url += "?" + query
        with self.opener.open(url, timeout=3) as response:
            return response.status, json.load(response)

    def get_with_host(self, path, host):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        request = Request(url, headers={"Host": host})
        with self.opener.open(request, timeout=3) as response:
            return response.status, json.load(response)

    def test_filter_and_mapping_include_historical_dhcp_context(self):
        status, body = self.get("type=dhcp&ip=192.168.1.20")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"]["state"], "ready")
        self.assertEqual(len(body["events"]), 1)
        event = body["events"][0]
        self.assertEqual(event["timestamp"], "2026-11-03T10:00:00-10:00")
        self.assertEqual(event["sender"], "192.0.2.10")
        self.assertEqual(event["client_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(event["allocated_ip"], "192.168.1.20")
        self.assertIn("DHCP Server allocated", event["source_event"])
        self.assertEqual(event["parse_status"], "parsed")
        self.assertIn("historical", body["interpretation"])

    def test_custom_event_file_is_used(self):
        custom_path = os.path.join(self.tmp.name, "custom", "index.sqlite3")
        os.makedirs(os.path.dirname(custom_path))
        custom = store.EventStore(custom_path, self.raw_path, 8 * 1024 * 1024)
        custom.add("2026-11-03T11:00:00-10:00", "192.0.2.99", [b"<134>custom store record"])
        custom.close()
        self.server.args.event_file = custom_path
        _, body = self.get("q=custom+store+record")
        self.assertEqual(len(body["events"]), 1)
        self.assertEqual(body["events"][0]["sender"], "192.0.2.99")

    def test_text_sender_activity_sort_and_stable_cursor_pages(self):
        _, descending = self.get("type=all&sender=192.0.2.10&limit=2&sort=received_at_desc")
        self.assertEqual([e["id"] for e in descending["events"]], sorted(
            [e["id"] for e in descending["events"]], reverse=True))
        self.assertIsNotNone(descending["next_cursor"])
        writer = store.EventStore(self.db_path, self.raw_path, 8 * 1024 * 1024)
        writer.add("2026-11-03T10:03:00-10:00", "192.0.2.10", [b"<134>appended after first page"])
        writer.close()
        _, older = self.get("type=all&sender=192.0.2.10&limit=2&sort=received_at_desc&cursor=" + descending["next_cursor"])
        self.assertEqual(len(older["events"]), 1)
        self.assertNotIn("appended after first page", older["events"][0]["source_event"])
        with self.assertRaises(HTTPError) as mismatched:
            self.get("type=all&sender=192.0.2.11&limit=2&sort=received_at_desc&cursor=" + descending["next_cursor"])
        try:
            self.assertEqual(mismatched.exception.code, 400)
        finally:
            mismatched.exception.close()
        self.assertNotEqual(older["events"][0]["id"], descending["events"][0]["id"])
        _, mac = self.get("activity=client_roaming&mac=aa:bb:cc:dd:ee:02")
        self.assertEqual(len(mac["events"]), 1)
        _, text = self.get("q=opaque+original+record")
        self.assertEqual(len(text["events"]), 1)
        _, ascending = self.get("type=dhcp&sort=received_at_asc")
        self.assertEqual([e["allocated_ip"] for e in ascending["events"]],
                         ["192.168.1.20", "192.168.1.21"])

    def test_invalid_inputs_are_rejected(self):
        for query in ("type=nope", "limit=201", "mac=bad", "sender=not-an-ip",
                      "since=not-a-time", "sort=raw", "unknown=x", "limit=1&limit=2"):
            with self.subTest(query=query):
                with self.assertRaises(HTTPError) as raised:
                    self.get(query)
                try:
                    self.assertEqual(raised.exception.code, 400)
                finally:
                    raised.exception.close()

    def test_missing_sender_is_preserved_as_malformed_row(self):
        _, body = self.get("type=all&q=orphan+record")
        self.assertEqual(len(body["events"]), 1)
        self.assertIsNone(body["events"][0]["sender"])
        self.assertEqual(body["events"][0]["parse_status"], "malformed")

    def test_missing_database_reports_unavailable_not_empty_history(self):
        self.db.close()
        os.remove(self.db_path)
        _, body = self.get()
        self.assertEqual(body["status"]["state"], "unavailable")
        self.assertEqual(body["events"], [])
        self.assertIn("unavailable", body["note"])

    def test_corrupt_store_status_is_server_error_not_invalid_query(self):
        for diagnostic in ("{broken", "[]"):
            with self.subTest(diagnostic=diagnostic):
                with open(self.db_path + ".errors.json", "w", encoding="utf-8") as stream:
                    stream.write(diagnostic)
                with self.assertRaises(HTTPError) as raised:
                    self.get("type=all")
                try:
                    self.assertEqual(raised.exception.code, 503)
                    self.assertIn(b"status is unreadable", raised.exception.read())
                finally:
                    raised.exception.close()

    def test_backfill_state_distinguishes_partial_history_from_empty(self):
        history_path = os.path.join(self.tmp.name, "history", "firewall.log")
        os.makedirs(os.path.dirname(history_path))
        with open(history_path, "w", encoding="utf-8") as stream:
            stream.write("2026-11-03T09:00:00-10:00\t192.0.2.25\t<134>prior event\n")
        backfill_db = store.EventStore(store.default_event_path(history_path), history_path,
                                       8 * 1024 * 1024)
        backfill_db.close()
        self.server.args.log_file = history_path
        self.server.args.event_file = store.default_event_path(history_path)
        _, body = self.get()
        self.assertEqual(body["status"]["state"], "backfilling")
        self.assertEqual(body["status"]["legacy_state"], "pending")
        self.assertGreater(body["status"]["legacy_total_bytes"], body["status"]["legacy_imported_bytes"])

    def test_remote_request_is_forbidden(self):
        handler = object.__new__(viz.Handler)
        handler.path = "/api/recorded-events?type=all"
        handler.client_address = ("192.0.2.55", 12345)
        handler.server = SimpleNamespace(args=SimpleNamespace(log_file=self.raw_path))
        sent = {}
        handler._send = lambda status, content_type, payload: sent.update(
            status=status, content_type=content_type, payload=payload)
        viz.Handler.do_GET(handler)
        self.assertEqual(sent["status"], 403)
        self.assertIn(b"localhost only", sent["payload"])

    def test_local_sensitive_routes_reject_rebinding_host_and_accept_local_hosts(self):
        for path in ("/api/events?limit=1", "/api/recorded-events?type=all", "/api/data"):
            with self.subTest(path=path):
                try:
                    self.get_with_host(path, "attacker.example:%d" % self.port)
                    self.fail("malicious Host should be rejected")
                except HTTPError as raised:
                    try:
                        self.assertEqual(raised.code, 403)
                    finally:
                        raised.close()
                for local_host in ("localhost:%d" % self.port, "127.0.0.1:%d" % self.port):
                    status, _ = self.get_with_host(path, local_host)
                    self.assertEqual(status, 200)
        self.assertTrue(viz._local_host_header_allowed("[::1]:8780", server_port=8780))

    def test_ipv6_loopback_host_when_available(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 is unavailable")

        class IPv6VizServer(viz.VizServer):
            address_family = socket.AF_INET6

        try:
            server = IPv6VizServer(("::1", 0), viz.Handler)
        except OSError as error:
            self.skipTest("IPv6 loopback bind is unavailable: %s" % error)
        server.args = SimpleNamespace(log_file=self.raw_path, event_file=self.db_path,
                                      html_dir=self.tmp.name, raw_tail=10,
                                      condense_file=os.path.join(self.tmp.name, "condensed.json"),
                                      recovery_status_file=os.path.join(self.tmp.name, "recovery.json"))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = server.socket.getsockname()[1]
            url = "http://[::1]:%d/api/events?limit=1" % port
            with self.opener.open(url, timeout=3) as response:
                self.assertEqual(response.status, 200)
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()


if __name__ == "__main__":
    unittest.main()
