"""Focused CLI tests for syslog PRI facility decoding."""

import os
import subprocess
import sys
import tempfile
import unittest


PARSER = os.path.join(os.path.dirname(__file__), "syslog_parser.py")


class FacilityDecodingTests(unittest.TestCase):
    def run_parser(self, rows):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "firewall.log")
            with open(path, "w", encoding="utf-8", newline="") as log:
                log.write("\n".join(rows) + "\n")
            return subprocess.run(
                [sys.executable, PARSER, "--log-file", path],
                check=True, capture_output=True, text=True,
            ).stdout.splitlines()

    def test_all_local_facilities_are_named(self):
        rows = ["2026-11-03T00:00:00.000-10:00\t192.0.2.1\t<%d>sample" % pri
                for pri in range(128, 192)]
        output = self.run_parser(rows)
        self.assertEqual(len(output), 64)
        for facility_id in range(16, 24):
            pri = facility_id * 8
            self.assertIn("local%d.emerg" % (facility_id - 16), output[pri - 128])

    def test_malformed_and_out_of_range_pri_remain_printable(self):
        rows = [
            "2026-11-03T00:00:00.000-10:00\t192.0.2.1\t<192>too-large",
            "2026-11-03T00:00:01.000-10:00\t192.0.2.1\t<bad>malformed",
        ]
        output = self.run_parser(rows)
        self.assertEqual(len(output), 2)
        self.assertTrue(output[0].endswith("<192>too-large"))
        self.assertTrue(output[1].endswith("<bad>malformed"))


if __name__ == "__main__":
    unittest.main()
