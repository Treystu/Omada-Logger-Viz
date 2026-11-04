#!/usr/bin/env python3
"""Focused tests for receiver heartbeat scheduling (no host task changes)."""

import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

from omada_condenser import Condenser
import omada_syslog


class HeartbeatTests(unittest.TestCase):
    def test_refresh_creates_parent_and_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state", "receiver.heartbeat")
            omada_syslog.refresh_heartbeat(path)
            self.assertTrue(os.path.isfile(path))

    def test_idle_loop_refreshes_only_after_interval(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "receiver.heartbeat")
            omada_syslog.refresh_heartbeat(path)
            first = os.stat(path).st_mtime_ns

            last = omada_syslog.refresh_heartbeat_if_due(path, 10.0, 14.9, 5.0)
            self.assertEqual(last, 10.0)
            self.assertEqual(os.stat(path).st_mtime_ns, first)

            last = omada_syslog.refresh_heartbeat_if_due(path, last, 15.0, 5.0)
            self.assertEqual(last, 15.0)
            self.assertGreaterEqual(os.stat(path).st_mtime_ns, first)

    def test_large_catch_up_reports_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            raw = os.path.join(tmp, "raw.log")
            state = os.path.join(tmp, "condensed.json")
            with open(raw, "w", encoding="utf-8") as f:
                for i in range(1024):
                    f.write("2026-11-03T00:00:00.000-10:00\t127.0.0.1\t<134>message %d\n" % i)
            calls = []
            cond = Condenser(state, 1_000_000)
            folded = cond.catch_up(raw, progress=lambda: calls.append(1))
            self.assertEqual(folded, 1024)
            self.assertGreaterEqual(len(calls), 8)

    def test_idle_receiver_refreshes_heartbeat_without_log_traffic(self):
        with tempfile.TemporaryDirectory() as tmp:
            appdata = os.path.join(tmp, "appdata")
            os.makedirs(appdata)
            log = os.path.join(tmp, "firewall.log")
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
            probe.close()

            env = os.environ.copy()
            env["LOCALAPPDATA"] = appdata
            code = ("import omada_syslog,sys; "
                    "omada_syslog.HEARTBEAT_INTERVAL_S=0.2; "
                    "sys.exit(omada_syslog.main(sys.argv[1:]))")
            proc = subprocess.Popen(
                [sys.executable, "-c", code, "--bind", "127.0.0.1", "--port", str(port),
                 "--allow", "127.0.0.1", "--log-file", log, "--no-condense"],
                cwd=os.path.dirname(os.path.abspath(__file__)), env=env,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            heartbeat = os.path.join(appdata, "OmadaSyslog", "receiver.heartbeat")
            try:
                deadline = time.time() + 5
                while time.time() < deadline and not os.path.exists(heartbeat):
                    if proc.poll() is not None:
                        self.fail("receiver exited before publishing heartbeat")
                    time.sleep(0.05)
                self.assertTrue(os.path.exists(heartbeat), "receiver did not publish initial heartbeat")
                first = os.stat(heartbeat).st_mtime_ns
                deadline = time.time() + 3
                while time.time() < deadline and os.stat(heartbeat).st_mtime_ns == first:
                    time.sleep(0.05)
                self.assertGreater(os.stat(heartbeat).st_mtime_ns, first)
                self.assertEqual(os.path.getsize(log), 0, "heartbeat advanced despite no raw syslog traffic")
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()


if __name__ == "__main__":
    unittest.main()
