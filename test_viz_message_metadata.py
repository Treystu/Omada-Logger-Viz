"""Tests for preserving source and syslog header metadata in visualization records."""

import unittest
import json
import os
import tempfile
from types import SimpleNamespace

import omada_viz


class VisualizationMessageMetadataTests(unittest.TestCase):
    def test_missing_pri_keeps_message_and_sender_without_guessing_facility(self):
        record = omada_viz.parse_raw_line("2026-11-03T00:00:00Z\t192.0.2.9\tplain event body")
        self.assertEqual(record["sender"], "192.0.2.9")
        self.assertEqual(record["message"], "plain event body")
        self.assertNotIn("pri", record)
        self.assertNotIn("facility", record)

    def test_rfc3164_metadata_and_original_body_are_preserved(self):
        raw = "<134>Nov  3 12:34:56 gateway alertd[42]: disk pressure"
        record = omada_viz.parse_raw_line("2026-11-03T00:00:00Z\t192.0.2.9\t" + raw)
        self.assertEqual((record["pri"], record["facility_id"], record["facility"], record["sev"]),
                         (134, 16, "local0", 6))
        self.assertEqual((record["hostname"], record["tag"], record["procid"]),
                         ("gateway", "alertd", "42"))
        self.assertEqual(record["message"], raw)

    def test_rfc5424_metadata_is_extracted_only_from_valid_header(self):
        raw = '<134>1 2026-11-03T12:34:56Z gateway alertd 42 EVT1 [meta a="b"] disk pressure'
        record = omada_viz.parse_raw_line("2026-11-03T00:00:00Z\t192.0.2.9\t" + raw)
        self.assertEqual((record["hostname"], record["tag"], record["procid"], record["msgid"]),
                         ("gateway", "alertd", "42", "EVT1"))
        self.assertEqual(record["structured_data"], '[meta a="b"]')
        self.assertEqual(record["message"], raw)

    def test_flow_client_src_and_receiver_sender_are_distinct(self):
        raw = "<6>IP SRC=10.0.0.2 IP DST=8.8.8.8 IP proto=17 SPT=1234 DPT=53"
        record = omada_viz.parse_raw_line("2026-11-03T00:00:00Z\t192.0.2.9\t" + raw)
        self.assertEqual(record["src"], "10.0.0.2")
        self.assertEqual(record["sender"], "192.0.2.9")

    def test_remote_api_redacts_original_messages_but_keeps_chart_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            condensed_path = os.path.join(tmp, "condensed.json")
            raw_path = os.path.join(tmp, "firewall.log")
            with open(condensed_path, "w", encoding="utf-8") as f:
                json.dump({"message-key": {"type": "msg", "template": "alert from <ip>",
                                            "sample": "secret sample", "count": 3}}, f)
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write("2026-11-03T00:00:00Z\t192.0.2.9\t<134>Nov  3 12:34:56 gateway alertd[42]: secret body\n")
                f.write("2026-11-03T00:00:01Z\t192.0.2.9\t<6>IP SRC=10.0.0.2 IP DST=8.8.8.8 IP proto=17 DPT=53\n")
            args = SimpleNamespace(log_file=raw_path, condense_file=condensed_path,
                                   raw_tail=10, recovery_status_file=os.path.join(tmp, "missing.json"))

            def request(peer):
                handler = object.__new__(omada_viz.Handler)
                handler.path = "/api/data"
                handler.client_address = (peer, 1)
                handler.headers = {"Host": "localhost:8780"}
                handler.server = SimpleNamespace(args=args, server_port=8780,
                                                 server_address=("127.0.0.1", 8780))
                captured = {}
                handler._send = lambda status, content_type, body: captured.update(
                    status=status, payload=json.loads(body))
                omada_viz.Handler.do_GET(handler)
                self.assertEqual(captured["status"], 200)
                return captured["payload"]

            local = request("127.0.0.1")
            local_message = next(r for r in local["raw"] if r["type"] == "msg")
            self.assertEqual(local["entries"][0]["sample"], "secret sample")
            self.assertIn("secret body", local_message["message"])

            remote = request("192.0.2.20")
            remote_message = next(r for r in remote["raw"] if r["type"] == "msg")
            self.assertEqual(remote["entries"][0]["template"], "alert from <ip>")
            self.assertNotIn("sample", remote["entries"][0])
            self.assertNotIn("message", remote_message)
            self.assertNotIn("secret", remote_message["label"])
            self.assertNotIn("structured_data", remote_message)
            self.assertEqual(remote_message["facility"], "local0")
            remote_flow = next(r for r in remote["raw"] if r["type"] == "flow")
            self.assertEqual(remote_flow["label"], "10.0.0.2 -> 8.8.8.8 17/53")


if __name__ == "__main__":
    unittest.main()
