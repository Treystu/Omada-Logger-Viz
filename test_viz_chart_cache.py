import gzip
import io
import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import urlencode

import omada_chart_cache as cache
import omada_viz as viz


STAMP = "2026-11-03T13:00:00.000-10:00"
SAMPLE = "<134>DHCP allocated IP address 192.0.2.44 to client aa:bb:cc:dd:ee:ff"
LONG = "<134>" + "x" * 160 + " private-token"


def line(message):
    return f"{STAMP}\t192.0.2.1\t{message}\n"


def tally(count=1, sample=SAMPLE):
    return {"type": "msg", "from": "192.0.2.1", "sev": 6, "count": count,
            "first": STAMP, "last": STAMP, "occurrences": [STAMP],
            "template": "DHCP aggregate", "sample": sample}


def apply_changes(snapshot, change):
    result = {layer: {row["id"]: row for row in snapshot[layer]} for layer in cache.LAYERS}
    for edit in change["changes"]:
        rows = result[edit["layer"]]
        for row_id in edit["deletes"]:
            rows.pop(row_id, None)
        rows.update({row["id"]: row for row in edit["upserts"]})
    return {layer: sorted(rows.values(), key=lambda row: row["order"])
            for layer, rows in result.items()}


class ChartTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        self.args = SimpleNamespace(condense_file=base / "condensed.json", log_file=base / "raw.log",
                                    raw_tail=3, recovery_status_file=base / "recovery.json")
        self.args.log_file.write_text(line(LONG) * 2 + "malformed\n", encoding="utf-8", newline="")
        self.write_tallies(a=tally(), b=tally(3))
        self.chart = viz._new_chart(self.args)

    def write_tallies(self, **entries):
        temp = self.args.condense_file.with_suffix(".tmp")
        temp.write_text(json.dumps({**entries, "_meta": {"keys": len(entries), "private": "hidden"}}),
                        encoding="utf-8")
        os.replace(temp, self.args.condense_file)

    def test_snapshot_preserves_duplicates_redacts_and_loads_detail_on_request(self):
        local = self.chart.snapshot(True)
        remote = self.chart.snapshot(False)
        self.assertTrue(local["detail_available"])
        self.assertFalse(remote["detail_available"])
        self.assertFalse(local["redacted_detail_available"])
        self.assertTrue(remote["redacted_detail_available"])
        self.assertEqual(local["revision"], remote["revision"])
        self.assertEqual(local["sources"]["raw"], {"available": True, "records": 2, "unparsed": 1})
        first, second = local["raw"]
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(first["pattern_id"], second["pattern_id"])
        self.assertLess(first["order"], second["order"])
        self.assertEqual(first["label"], LONG[:90])
        self.assertNotIn("pattern_id", remote["raw"][0])
        self.assertEqual(remote["raw"][0]["label"], cache.REMOTE_MESSAGE_LABEL)
        for snapshot in (local, remote):
            chart_json = json.dumps(snapshot)
            self.assertNotIn("private-token", chart_json)
            self.assertNotIn(SAMPLE, chart_json)
            self.assertNotIn("structured_data", chart_json)
            self.assertEqual(snapshot["meta"], {"keys": 2})
        refs = [(row["id"], row["version"]) for row in (first, local["entries"][0])]
        details = self.chart.details(local["epoch"], refs)["results"]
        self.assertEqual(details[0]["record"]["message"], LONG)
        self.assertEqual(details[1]["record"]["sample"], SAMPLE)
        legacy = viz.build_payload(self.args)
        self.assertEqual(legacy["raw"][0]["message"], LONG)
        self.assertEqual(legacy["entries"][0]["sample"], SAMPLE)

    def test_changes_are_repeatable_and_keep_published_rows_consistent(self):
        first = self.chart.snapshot(True)
        old_raw, retained_raw = first["raw"]
        old_tally, deleted_tally = first["entries"]
        self.write_tallies(a=tally(2), c=tally(4))
        with self.args.log_file.open("a", encoding="utf-8", newline="") as log:
            log.write(line("<134>new"))
        # Detail looks up the exact published reference until the next update.
        self.assertEqual(self.chart.details(first["epoch"], [(old_tally["id"], old_tally["version"])],
                                            single=True)["record"]["count"], 1)
        with ThreadPoolExecutor(max_workers=2) as clients:
            futures = [clients.submit(self.chart.changes, first["epoch"], first["revision"], True)
                       for _ in range(2)]
            left, right = [future.result() for future in futures]
        self.assertEqual(left, right)
        self.assertEqual(left["base"], first["revision"])
        fresh = self.chart.snapshot(True)
        self.assertEqual(apply_changes(first, left), {key: fresh[key] for key in cache.LAYERS})
        self.assertEqual(fresh["raw"][0], retained_raw)
        self.assertEqual(fresh["entries"][0]["id"], old_tally["id"])
        self.assertNotEqual(fresh["entries"][0]["version"], old_tally["version"])
        refs = [(row["id"], row["version"]) for row in (old_raw, deleted_tally, old_tally)]
        self.assertEqual([r["status"] for r in self.chart.details(first["epoch"], refs)["results"]],
                         [404, 404, 409])
        unchanged = self.chart.changes(first["epoch"], fresh["revision"], True)
        self.assertEqual(set(unchanged), {"schema", "epoch", "revision", "base", "changes"})
        self.assertEqual(unchanged["changes"], [])

    def test_truncate_rotate_restart_and_source_recovery(self):
        first = self.chart.snapshot(True)
        replacement = self.args.log_file.with_suffix(".tmp")
        replacement.write_bytes(self.args.log_file.read_bytes())
        os.replace(replacement, self.args.log_file)
        with self.assertRaises(cache.ChartError) as rotated:
            self.chart.changes(first["epoch"], first["revision"], True)
        self.assertTrue(rotated.exception.details["reset"])
        second = self.chart.snapshot(True)
        self.assertNotEqual(first["raw"][0]["id"], second["raw"][0]["id"])
        self.args.log_file.write_text("", encoding="utf-8")
        with self.assertRaises(cache.ChartError):
            self.chart.changes(second["epoch"], second["revision"], True)
        self.args.log_file.unlink()
        self.args.condense_file.write_text("[", encoding="utf-8")
        unavailable = self.chart.snapshot(True)
        self.assertTrue(all(not v["available"] for v in unavailable["sources"].values()))
        self.args.log_file.write_text(line(LONG), encoding="utf-8")
        self.write_tallies(a=tally())
        recovery = self.chart.changes(unavailable["epoch"], unavailable["revision"], True)
        self.assertTrue(all(v["available"] for v in recovery["sources"].values()))
        with self.assertRaises(cache.ChartError):
            viz._new_chart(self.args).changes(unavailable["epoch"], unavailable["revision"], True)

    def test_append_remains_incremental_when_all_previous_rows_leave_tail(self):
        self.args.raw_tail = 1
        self.args.log_file.write_bytes(line(LONG).encode("utf-8"))
        first = self.chart.snapshot(True)
        for count in (1, 4):
            with self.args.log_file.open("ab") as log:
                log.write(line(LONG).encode("utf-8") * count)
            change = self.chart.changes(first["epoch"], first["revision"], True)
            fresh = self.chart.snapshot(True)
            self.assertEqual(apply_changes(first, change)["raw"], fresh["raw"])
            self.assertEqual(change["changes"][0]["deletes"], [first["raw"][0]["id"]])
            self.assertNotEqual(first["raw"][0]["id"], fresh["raw"][0]["id"])
            self.assertEqual(first["raw"][0]["pattern_id"], fresh["raw"][0]["pattern_id"])
            self.assertLess(first["raw"][0]["order"], fresh["raw"][0]["order"])
            first = fresh

    def test_same_inode_truncate_and_regrow_with_changed_anchor_requires_reset(self):
        self.args.raw_tail = 1
        self.args.log_file.write_bytes(line(LONG).encode("utf-8"))
        first = self.chart.snapshot(True)
        before = self.args.log_file.stat()
        with self.args.log_file.open("wb") as log:
            log.write(line("<134>replacement").encode("utf-8") * 10)
        after = self.args.log_file.stat()
        self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
        self.assertLess(before.st_size, after.st_size)
        with self.assertRaises(cache.ChartError) as error:
            self.chart.changes(first["epoch"], first["revision"], True)
        self.assertTrue(error.exception.details["reset"])
        self.assertNotEqual(first["raw"][0]["id"], self.chart.snapshot(True)["raw"][0]["id"])

    def test_custom_raw_limits_project_small_sources_and_fallback_when_oversized(self):
        for limit, oversized in ((0, b"\n" * (cache.RAW_SCAN_CHUNK + 1)),
                                 (cache.MAX_ROWS + 10, b"\n" * (cache.MAX_ROWS + 1))):
            with self.subTest(limit=limit):
                self.args.raw_tail = limit
                self.args.log_file.write_bytes(line(LONG).encode("utf-8") * 4)
                self.chart = viz._new_chart(self.args)
                status, snapshot, _ = self.http("/api/chart/snapshot")
                self.assertEqual(status, 200)
                legacy = viz.build_payload(self.args)
                self.assertEqual([row["label"] for row in snapshot["raw"]],
                                 [row["label"] for row in legacy["raw"]])
                self.assertTrue(snapshot["sources"]["raw"]["available"])
                self.assertEqual(len(snapshot["raw"]), 4)

                self.args.log_file.write_bytes(oversized)
                self.write_tallies(a=tally(2))
                delta_path = f"/api/chart/changes?epoch={snapshot['epoch']}&since={snapshot['revision']}"
                for path in (delta_path, "/api/chart/snapshot"):
                    code, result, _ = self.http(path)
                    self.assertEqual(code, 501)
                    self.assertTrue(result["fallback"])
                self.assertTrue(viz.build_payload(self.args)["sources"]["raw"]["available"])

                self.args.log_file.write_bytes(line(LONG).encode("utf-8"))
                fresh = self.chart.snapshot(True)
                self.assertEqual(fresh["entries"][0]["count"], 2)
                self.assertEqual(len(fresh["raw"]), 1)

    def test_oversized_condensed_source_returns_legacy_fallback_without_publishing_partial_refresh(self):
        before = self.chart.snapshot(True)
        old_layers = self.chart.layers
        old_status = self.chart.status
        old_raw_state = self.chart.raw_state
        old_signature = self.chart.tally_signature
        old_history = list(self.chart.history)

        self.write_tallies(a={**tally(2), "large": "x" * 256})
        size = self.args.condense_file.stat().st_size
        with patch.object(cache, "MAX_SOURCE_BYTES", size - 1):
            for path in ("/api/chart/snapshot",
                         f"/api/chart/changes?epoch={before['epoch']}&since={before['revision']}"):
                status, result, _ = self.http(path)
                self.assertEqual(status, 501)
                self.assertTrue(result["fallback"])
                self.assertIn("condensed", result["error"].lower())

        self.assertEqual(self.chart.revision, before["revision"])
        self.assertIs(self.chart.layers, old_layers)
        self.assertIs(self.chart.status, old_status)
        self.assertIs(self.chart.raw_state, old_raw_state)
        self.assertEqual(self.chart.tally_signature, old_signature)
        self.assertEqual(list(self.chart.history), old_history)

        # Recovery publishes the valid new state as one consistent revision.
        self.write_tallies(a=tally(2), b=tally(3))
        recovered = self.chart.snapshot(True)
        self.assertEqual(recovered["revision"], before["revision"] + 1)
        delta = self.chart.changes(before["epoch"], before["revision"], True)
        self.assertEqual(apply_changes(before, delta), {key: recovered[key] for key in cache.LAYERS})
        self.assertEqual([row["count"] for row in recovered["entries"]], [2, 3])

    def test_history_bounds_and_recreated_tally(self):
        first = self.chart.snapshot(True)
        self.write_tallies(a=tally(1), b=tally(1))
        updated = self.chart.snapshot(True)
        self.assertNotEqual(first["entries"][1]["id"], updated["entries"][1]["id"])
        with patch.object(cache, "MAX_HISTORY", 1):
            self.write_tallies(a=tally(2), b=tally(1))
            self.chart.snapshot(True)
            self.write_tallies(a=tally(3), b=tally(1))
            self.chart.snapshot(True)
            with self.assertRaises(cache.ChartError):
                self.chart.changes(first["epoch"], updated["revision"], True)
        with patch.object(cache, "MAX_DELTA_ROWS", 1):
            updated = self.chart.snapshot(True)
            self.write_tallies(c=tally(), d=tally())
            with self.assertRaises(cache.ChartError):
                self.chart.changes(first["epoch"], updated["revision"], True)

    def http(self, path, local=True, host="localhost:8780", data=None, encoding=""):
        handler = object.__new__(viz.Handler)
        handler.path = path
        handler.client_address = ("127.0.0.1" if local else "192.0.2.50", 60000)
        handler.server = SimpleNamespace(args=self.args, server_port=8780, chart=lambda: self.chart)
        handler.headers = Message()
        handler.headers["Host"] = host
        handler.headers["Accept-Encoding"] = encoding
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            handler.headers["Content-Type"] = "application/json"
            handler.headers["Content-Length"] = str(len(body))
            handler.rfile = io.BytesIO(body)
        calls = []
        handler._send = lambda status, ctype, body, headers=None: calls.append((status, body, headers or {}))
        (handler.do_GET if data is None else handler.do_POST)()
        status, body, headers = calls[0]
        if headers.get("Content-Encoding") == "gzip":
            body = gzip.decompress(body)
        return status, json.loads(body), headers

    def test_http_permissions_search_validation_and_gzip(self):
        path = "/api/chart/snapshot"
        self.assertEqual(self.http(path, host="untrusted.example")[0], 403)
        status, local, headers = self.http(path, encoding="gzip")
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("Content-Encoding"), "gzip")
        self.assertNotIn("Content-Encoding", self.http(path, encoding="*;q=1,gzip;q=0")[2])
        detail = "/api/chart/detail?" + urlencode({"epoch": local["epoch"],
                                                     "id": local["raw"][0]["id"],
                                                     "version": local["raw"][0]["version"]})
        status, remote_detail, _ = self.http(detail, local=False)
        self.assertEqual(status, 200)
        self.assertEqual(remote_detail["record"]["label"], cache.REMOTE_MESSAGE_LABEL)
        self.assertNotIn("message", remote_detail["record"])
        self.assertEqual(self.http(detail)[1]["record"]["message"], LONG)
        params = {k: local[k] for k in ("schema", "epoch", "revision")}
        search = "/api/chart/search"
        exact = self.http(search, data={**params, "q": "private-token"})[1]
        self.assertEqual(exact["matches"]["pattern"], [row["id"] for row in local["raw"]])
        remote = self.http(search, local=False, data={**params, "q": "private-token"})[1]
        self.assertTrue(all(not matches for matches in remote["matches"].values()))
        self.assertEqual(self.http(search, data={**params, "q": "x", "revision": 999})[0], 409)
        self.assertEqual(self.http(search, data={**params, "q": "x", "revision": True})[0], 400)
        self.assertEqual(self.http(f"/api/chart/changes?epoch={local['epoch']}&since=-1")[0], 400)
        self.assertEqual(self.http(f"/api/chart/changes?epoch={local['epoch']}&since=1&since=2")[0], 400)

    def test_remote_details_match_legacy_permitted_records(self):
        header = '<134>1 2026-11-03T12:34:56Z router firewall 42 EVT1 [meta a="secret-sd"] '
        raw_flow = header + "IP SRC=10.0.0.2 IP DST=192.0.2.9 IP proto=17 SPT=1234 DPT=53"
        raw_message = header + "secret-body"
        self.args.log_file.write_text(line(raw_flow) + line(raw_message), encoding="utf-8", newline="")
        flow = {"type": "flow", "src": "10.0.0.2", "dst": "192.0.2.9", "proto": 17,
                "dpt": 53, "spt_sample": 1234, "count": 3, "last": STAMP}
        self.write_tallies(flow=flow, msg=tally())
        _, snapshot, _ = self.http("/api/chart/snapshot", local=False)
        legacy = viz.redact_remote_payload(viz.build_payload(self.args))
        refs = [{"id": row["id"], "version": row["version"]}
                for key in cache.LAYERS for row in snapshot[key]]
        payload = {"schema": 1, "epoch": snapshot["epoch"], "refs": refs}
        status, redacted, _ = self.http("/api/chart/details", local=False, data=payload)
        self.assertEqual(status, 200)
        self.assertEqual([result["record"] for result in redacted["results"]],
                         legacy["entries"] + legacy["raw"])
        redacted_json = json.dumps(redacted)
        for secret in ("secret-sd", "secret-body", SAMPLE, "aa:bb:cc:dd:ee:ff"):
            self.assertNotIn(secret, redacted_json)
        self.assertEqual(self.http("/api/chart/details", host="untrusted.example", data=payload)[0], 403)
        self.assertEqual(self.http("/api/events", local=False)[0], 403)
        self.assertEqual(self.http("/api/recorded-events", local=False)[0], 403)


if __name__ == "__main__":
    unittest.main()
