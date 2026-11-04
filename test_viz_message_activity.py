"""Message format, activity and candidate extraction regression tests."""

import json
import os
import tempfile
import unittest
from types import SimpleNamespace

import omada_viz


class MessageExtractionTests(unittest.TestCase):
    def parse(self, raw):
        return omada_viz.parse_raw_line("2026-11-03T00:00:00Z\t192.0.2.10\t" + raw)

    def test_observed_omada_v1_space_timestamp_and_dhcp_activity(self):
        raw = "<134>1 2026-11-02 17:45:09 host - - - DHCP Server allocated IP address 192.0.2.4 for the [client:02:00:00:00:00:01 ]."
        record = self.parse(raw)
        self.assertEqual(record["message"], raw)
        self.assertEqual(record["syslog_format"], "omada-v1")
        self.assertEqual(record["syslog_timestamp"], "2026-11-02 17:45:09")
        self.assertEqual(record["message_body"], "DHCP Server allocated IP address 192.0.2.4 for the [client:02:00:00:00:00:01 ].")
        self.assertEqual(record["activity"]["id"], "dhcp_allocation")
        self.assertEqual(record["activity"]["variables"], {"ip": "192.0.2.4", "client_mac": "02:00:00:00:00:01"})
        self.assertIn({"kind": "ip", "value": "192.0.2.4"}, record["candidates"])

    def test_roaming_classification_and_address_candidates(self):
        body = "[client:02:00:00:00:00:01] is roaming from [ap:02:00:00:00:00:02][Channel 100] to [ap:02:00:00:00:00:03][Channel 6] with SSID guest-net."
        record = self.parse("<134>" + body)
        self.assertEqual(record["activity"]["id"], "client_roaming")
        self.assertEqual(record["activity"]["variables"]["from_channel"], "100")
        self.assertEqual(record["activity"]["variables"]["to_channel"], "6")
        self.assertEqual(record["activity"]["variables"]["ssid"], "guest-net")
        macs = [c["value"] for c in record["candidates"] if c["kind"] == "mac"]
        self.assertEqual(len(macs), 3)

    def test_rfc5424_multiple_structured_data_and_escaped_values(self):
        raw = '<134>1 2026-11-03T12:34:56Z gateway app 42 EVT [meta a="one\\\"two\\]three\\\\four"][other x=""] body'
        record = self.parse(raw)
        self.assertEqual(record["syslog_format"], "rfc5424")
        self.assertEqual(record["structured_data"], '[meta a="one\\\"two\\]three\\\\four"][other x=""]')
        self.assertEqual([x["id"] for x in record["structured_data_elements"]], ["meta", "other"])
        self.assertEqual(record["structured_data_elements"][0]["params"][0]["value"], 'one"two]three\\four')
        self.assertEqual(record["message_body"], "body")
        self.assertEqual(record["message"], raw)

    def test_rfc5424_nilvalue_and_empty_body(self):
        record = self.parse("<134>1 - - - - - -")
        self.assertEqual(record["syslog_format"], "rfc5424")
        self.assertTrue(record["structured_data_nil"])
        self.assertEqual(record["structured_data"], "-")
        self.assertEqual(record["message_body"], "")
        self.assertEqual(record["activity"]["id"], "unknown")

    def test_rfc5424_body_preserves_spaces_after_single_separator(self):
        sd = self.parse('<134>1 2026-11-03T12:34:56Z host app - EVT [meta a="b"]   begins with spaces')
        nil = self.parse('<134>1 2026-11-03T12:34:56Z host app - EVT -   begins with spaces')
        self.assertEqual(sd["message_body"], "  begins with spaces")
        self.assertEqual(nil["message_body"], "  begins with spaces")
        no_body = self.parse('<134>1 2026-11-03T12:34:56Z host app - EVT [meta a="b"]')
        self.assertEqual(no_body["message_body"], "")

    def test_wrapped_rfc3164_and_unknown_message_are_retained(self):
        raw = "<134>Nov  3 12:34:56 gateway dhcp_server[5]: [OMADA]unknown detail <tag>"
        record = self.parse(raw)
        self.assertEqual(record["tag"], "dhcp_server")
        self.assertEqual(record["procid"], "5")
        self.assertEqual(record["syslog_format"], "rfc3164")
        self.assertEqual(record["activity"]["id"], "unknown")
        self.assertEqual(record["message"], raw)
        self.assertIn("<tag>", record["message_body"])

    def test_omada_inner_tag_priority_wrapper_is_extracted(self):
        record = self.parse("<134>dhcp_server<5>: [OMADA]DHCP Server allocated IP address 192.0.2.9 for the [client:02:00:00:00:00:09 ].")
        self.assertEqual(record["tag"], "dhcp_server")
        self.assertEqual(record["inner_pri"], 5)
        self.assertEqual(record["syslog_format"], "omada-tag-wrapper")
        self.assertEqual(record["activity"]["id"], "dhcp_allocation")

    def test_connect_disconnect_transition(self):
        body = "[client:02:00:00:00:00:01] disconnected from SSID old-net on AP 02:00:00:00:00:02, then connected to SSID new-net on AP 02:00:00:00:00:03"
        record = self.parse("<134>" + body)
        self.assertEqual(record["activity"]["id"], "client_connection_transition")
        self.assertEqual(record["activity"]["variables"]["from_ssid"], "old-net")
        self.assertEqual(record["activity"]["variables"]["to_ssid"], "new-net")

    def test_ipv6_candidates_and_explicit_key_values(self):
        record = self.parse("<6>peer [2001:db8::1] ClientIP=192.0.2.8 SSID=lab")
        self.assertIn({"kind": "ip", "value": "2001:db8::1"}, record["candidates"])
        self.assertIn({"kind": "key_value", "role": "SSID", "value": "lab"}, record["candidates"])

    def test_ip_candidates_allow_punctuation_ports_and_key_prefixes(self):
        body = "Peer 192.0.2.1. Peer 192.0.2.1:443 Peer 2001:db8::1. IP:2001:db8::2"
        record = self.parse("<6>" + body)
        ips = {c["value"] for c in record["candidates"] if c["kind"] == "ip"}
        self.assertEqual(ips, {"192.0.2.1", "2001:db8::1", "2001:db8::2"})
        invalid = self.parse("<6>Peer 999.999.999.999:123")
        self.assertFalse([c for c in invalid["candidates"] if c["kind"] == "ip"])

    def test_remote_redaction_removes_structured_data_from_flow_records(self):
        raw = '<134>1 2026-11-03T12:34:56Z host app - EVT [secret token="sensitive"] IP SRC=10.0.0.2 IP DST=8.8.8.8 IP proto=17 DPT=53'
        record = self.parse(raw)
        self.assertEqual(record["type"], "flow")
        self.assertEqual(record["structured_data_elements"][0]["params"][0]["value"], "sensitive")
        omada_viz.redact_remote_payload({"entries": [], "raw": [record]})
        self.assertNotIn("structured_data", record)
        self.assertNotIn("structured_data_elements", record)

    def test_condensed_activity_is_explicitly_sample_only_and_remote_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            condensed = os.path.join(tmp, "condensed.json")
            raw_path = os.path.join(tmp, "firewall.log")
            with open(condensed, "w", encoding="utf-8") as f:
                json.dump({"m": {"type": "msg", "template": "DHCP allocation", "sample": "DHCP Server allocated IP address 192.0.2.4 for the [client:02:00:00:00:00:01 ].", "count": 8}}, f)
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write("2026-11-03T00:00:00Z\t192.0.2.10\t<134>DHCP Server allocated IP address 192.0.2.4 for the [client:02:00:00:00:00:01 ].\n")
            args = SimpleNamespace(log_file=raw_path, condense_file=condensed,
                                   raw_tail=10, recovery_status_file=os.path.join(tmp, "missing"))
            payload = omada_viz.build_payload(args)
            entry = payload["entries"][0]
            self.assertEqual(entry["activity"]["id"], "dhcp_allocation")
            self.assertTrue(entry["activity"]["sample_only"])
            self.assertEqual(entry["activity"]["coverage"], "single_sample")
            omada_viz.redact_remote_payload(payload)
            self.assertNotIn("sample", entry)
            self.assertNotIn("candidates", entry)
            self.assertNotIn("variables", entry["activity"])
            self.assertNotIn("message", payload["raw"][0])
            self.assertNotIn("message_body", payload["raw"][0])
            self.assertNotIn("candidates", payload["raw"][0])

    def test_unknown_condensed_sample_exposes_candidates_with_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            condensed = os.path.join(tmp, "condensed.json")
            raw_path = os.path.join(tmp, "firewall.log")
            sample = "Vendor notice for 192.0.2.44 client 02:00:00:00:00:44 key=value"
            with open(condensed, "w", encoding="utf-8") as f:
                json.dump({"unknown": {"type": "msg", "template": "Vendor notice", "sample": sample, "count": 2},
                           "no-sample": {"type": "msg", "template": "No observed details", "count": 1},
                           "empty-sample": {"type": "msg", "template": "DHCP Server allocated IP address 192.0.2.80 for the [client:02:00:00:00:00:80 ].", "sample": "", "count": 1}}, f)
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write("")
            args = SimpleNamespace(log_file=raw_path, condense_file=condensed,
                                   raw_tail=10, recovery_status_file=os.path.join(tmp, "missing"))
            payload = omada_viz.build_payload(args)
            observed = next(v for v in payload["entries"] if v.get("sample") == sample)
            self.assertEqual(observed["activity"]["id"], "unknown")
            self.assertTrue(observed["activity"]["sample_only"])
            self.assertEqual(observed["candidates_provenance"], {"sample_only": True, "coverage": "single_sample"})
            self.assertIn({"kind": "ip", "value": "192.0.2.44"}, observed["candidates"])
            self.assertIn({"kind": "mac", "value": "02:00:00:00:00:44"}, observed["candidates"])
            self.assertIn({"kind": "key_value", "role": "key", "value": "value"}, observed["candidates"])
            missing = next(v for v in payload["entries"] if v.get("template") == "No observed details")
            self.assertEqual(missing["candidates"], [])
            self.assertEqual(missing["candidates_provenance"], {"sample_only": True, "coverage": "no_sample"})
            empty = next(v for v in payload["entries"] if v.get("template", "").startswith("DHCP Server allocated IP address 192.0.2.80"))
            self.assertEqual(empty["activity"]["id"], "dhcp_allocation")
            self.assertEqual(empty["activity"]["coverage"], "template_only")
            self.assertEqual(empty["candidates"], [])
            self.assertEqual(empty["candidates_provenance"], {"sample_only": True, "coverage": "no_sample"})
            omada_viz.redact_remote_payload(payload)
            self.assertNotIn("candidates", observed)
            self.assertEqual(observed["candidates_provenance"], {"sample_only": True, "coverage": "single_sample"})

    def test_condensed_candidate_extraction_uses_parsed_syslog_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            condensed = os.path.join(tmp, "condensed.json")
            raw_path = os.path.join(tmp, "firewall.log")
            rfc = '<134>1 2026-11-03T12:34:56Z 192.0.2.9 app - EVT - address 10.0.0.5'
            omada = '<134>1 2026-11-02 17:45:09 192.0.2.10 - - - address 10.0.0.6'
            malformed = '<134>1 not-a-timestamp broken header 198.51.100.7'
            with open(condensed, "w", encoding="utf-8") as f:
                json.dump({str(i): {"type": "msg", "template": "unknown", "sample": sample}
                           for i, sample in enumerate((rfc, omada, malformed))}, f)
            with open(raw_path, "w", encoding="utf-8") as f:
                f.write("")
            args = SimpleNamespace(log_file=raw_path, condense_file=condensed,
                                   raw_tail=10, recovery_status_file=os.path.join(tmp, "missing"))
            entries = omada_viz.build_payload(args)["entries"]
            by_sample = {v["sample"]: v for v in entries}
            self.assertEqual([c["value"] for c in by_sample[rfc]["candidates"] if c["kind"] == "ip"], ["10.0.0.5"])
            self.assertEqual([c["value"] for c in by_sample[omada]["candidates"] if c["kind"] == "ip"], ["10.0.0.6"])
            self.assertEqual([c["value"] for c in by_sample[malformed]["candidates"] if c["kind"] == "ip"], ["198.51.100.7"])


if __name__ == "__main__":
    unittest.main()
