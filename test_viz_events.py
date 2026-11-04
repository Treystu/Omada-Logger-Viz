#!/usr/bin/env python3
"""Regression tests for bounded, snapshot-stable raw event browsing."""

import json
import os
import tempfile
import threading
import unittest
from types import SimpleNamespace
from urllib.request import ProxyHandler, build_opener

import omada_viz as viz


def fixture_lines(count):
    lines = []
    for i in range(count):
        timestamp = "2026-11-03T00:%02d:%02d.000-10:00" % ((i // 60) % 60, i % 60)
        if i % 3 == 0:
            raw = "<134>event %d with full message details" % i
            lines.append("%s\t127.0.0.1\t%s\n" % (timestamp, raw))
        elif i % 3 == 1:
            raw = ("<6>IP SRC=10.0.0.%d IP DST=8.8.8.8 IP proto=17 "
                   "SPT=%d DPT=53 AP MAC=aa:bb:cc:dd:ee:ff") % (i % 250, 1000 + i)
            lines.append("%s\t127.0.0.1\t%s\n" % (timestamp, raw))
        else:
            # Deliberately does not match the receiver's timestamp/sender/raw format.
            lines.append("BROKEN-ROW-%d\n" % i)
    return lines


class EventPaginationTests(unittest.TestCase):
    def test_pages_are_complete_and_append_stable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "firewall.log")
            source = fixture_lines(250)
            with open(path, "w", encoding="utf-8", newline="") as f:
                f.writelines(source)

            pages = []
            page_sizes = []
            page = viz.read_event_page(path, limit=100)
            snapshot = page["snapshot"]
            pages.extend(page["events"])
            page_sizes.append(len(page["events"]))

            # Later appends must not enter or invalidate the original snapshot.
            with open(path, "a", encoding="utf-8", newline="") as f:
                f.write("2026-11-03T01:00:00.000-10:00\t127.0.0.1\tappended after snapshot\n")

            cursor = page["next_before"]
            while page["has_older"]:
                page = viz.read_event_page(path, limit=100, before=cursor, snapshot=snapshot)
                pages.extend(page["events"])
                page_sizes.append(len(page["events"]))
                cursor = page["next_before"]

            expected = {line.rstrip("\n") for line in source}
            actual = [event["text"] for event in pages]
            self.assertEqual(page_sizes, [100, 100, 50])
            self.assertEqual(len(actual), 250)
            self.assertEqual(len({event["offset"] for event in pages}), 250)
            self.assertEqual(set(actual), expected)
            self.assertNotIn("appended after snapshot", "\n".join(actual))
            self.assertEqual(sum(event["type"] == "unparsed" for event in pages), 83)
            self.assertTrue(any(event["type"] == "msg" and
                                event["parsed"].get("message", "").endswith("event 0 with full message details")
                                for event in pages))
            self.assertTrue(any(event["type"] == "flow" and
                                event["parsed"].get("spt") == 1001 and
                                event["parsed"].get("ap") == "aa:bb:cc:dd:ee:ff"
                                for event in pages))

    def test_replacement_invalidates_existing_snapshot(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "firewall.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("2026-11-03T00:00:00.000-10:00\t127.0.0.1\t<134>old\n")
            page = viz.read_event_page(path)
            replacement = os.path.join(tmp, "replacement.log")
            with open(replacement, "w", encoding="utf-8") as f:
                f.write("2026-11-03T00:00:01.000-10:00\t127.0.0.1\t<134>new content\n")
            os.replace(replacement, path)

            with self.assertRaises(viz.EventPageError) as raised:
                viz.read_event_page(path, before=page["next_before"], snapshot=page["snapshot"])
            self.assertEqual(raised.exception.status, 409)

    def test_oversized_line_returns_explicit_413(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "firewall.log")
            with open(path, "wb") as f:
                f.write(b"x" * (viz.EVENT_LINE_MAX + 1) + b"\n")

            with self.assertRaises(viz.EventPageError) as raised:
                viz.read_event_page(path)
            self.assertEqual(raised.exception.status, 413)

    def test_http_route_is_loopback_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "firewall.log")
            with open(path, "w", encoding="utf-8") as f:
                f.write("2026-11-03T00:00:00.000-10:00\t127.0.0.1\t<134>loopback event\n")

            server = viz.VizServer(("127.0.0.1", 0), viz.Handler)
            server.args = SimpleNamespace(log_file=path, html_dir=tmp,
                                          condense_file=os.path.join(tmp, "condensed.json"),
                                          raw_tail=10, recovery_status_file=os.path.join(tmp, "recovery.json"))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                # The Windows exclusive-bind override leaves server_port at
                # zero for an ephemeral bind; getsockname reports the actual port.
                port = server.socket.getsockname()[1]
                url = "http://127.0.0.1:%d/api/events?limit=1" % port
                opener = build_opener(ProxyHandler({}))
                with opener.open(url, timeout=3) as response:
                    body = json.load(response)
                    self.assertEqual(response.status, 200)
                self.assertEqual(len(body["events"]), 1)
                self.assertIn("loopback event", body["events"][0]["text"])
            finally:
                server.shutdown()
                thread.join(timeout=3)
                server.server_close()

            # Exercise the request handler's non-loopback branch without opening
            # a network listener on any external interface.
            handler = object.__new__(viz.Handler)
            handler.path = "/api/events?limit=1"
            handler.client_address = ("192.0.2.1", 12345)
            handler.server = SimpleNamespace(args=SimpleNamespace(log_file=path))
            sent = {}
            handler._send = lambda status, content_type, payload: sent.update(
                status=status, content_type=content_type, payload=payload)
            viz.Handler.do_GET(handler)
            self.assertEqual(sent["status"], 403)
            self.assertIn(b"localhost only", sent["payload"])


if __name__ == "__main__":
    unittest.main()
