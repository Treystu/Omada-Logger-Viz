#!/usr/bin/env python3
"""Integration tests for omada_syslog.py (safe: high port 5151 + temp files).

Run:  python test_receiver.py
"""

import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
RECEIVER = os.path.join(HERE, "omada_syslog.py")
CONDENSER = os.path.join(HERE, "omada_condenser.py")
VIZ = os.path.join(HERE, "omada_viz.py")
PORT = 5151
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$")


def wait_port_taken(port, timeout=10):
    """True once the receiver has bound the port (second bind must fail)."""
    end = time.time() + timeout
    while time.time() < end:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind(("127.0.0.1", port))
        except OSError:
            s.close()
            return True
        s.close()
        time.sleep(0.2)
    return False


def send(payload, host="127.0.0.1"):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendto(payload, (host, PORT))
    finally:
        s.close()


def main():
    tmp = tempfile.mkdtemp(prefix="syslog-test-")
    logfile = os.path.join(tmp, "firewall.log")
    condfile = os.path.join(tmp, "cond.json")
    failures = []

    def check(name, cond, detail=""):
        print("[%s] %s%s" % ("PASS" if cond else "FAIL", name,
                             ("  (%s)" % detail) if not cond else ""))
        if not cond:
            failures.append(name)

    def read_lines():
        if not os.path.exists(logfile):
            return []
        with open(logfile, encoding="utf-8") as f:
            return f.read().splitlines()

    sys.path.insert(0, HERE)
    import omada_syslog as rec

    proc = subprocess.Popen(
        [sys.executable, RECEIVER, "--port", str(PORT), "--allow", "127.0.0.1",
         "--log-file", logfile, "--max-mb", "0.05",
         "--condense-file", condfile, "--condense-every", "60", "--occurrences", "3"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("receiver binds port", wait_port_taken(PORT))
        time.sleep(0.5)

        # 1. allowlist: datagram from the LAN IP (not in allowlist 127.0.0.1) is dropped
        lan_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))  # UDP connect: no packet is sent
            lan_ip = s.getsockname()[0]
            s.close()
        except OSError:
            pass
        if lan_ip and not lan_ip.startswith("127."):
            send(b"<134>Sep 21 10:00:00 ER8411 test: DROPPED", host=lan_ip)
            time.sleep(0.4)
            size = os.path.getsize(logfile) if os.path.exists(logfile) else 0
            check("allowlist drops non-authorized source", size == 0, "lan=%s size=%d" % (lan_ip, size))

        # 2. accepted line: format + raw payload preserved exactly
        send(b"<134>Sep 21 10:00:00 ER8411 test: hello world")
        time.sleep(0.4)
        with open(logfile, encoding="utf-8") as f:
            content = f.read()
        lines = content.splitlines()
        parts = lines[0].split("\t") if lines else []
        ok = (len(lines) == 1 and content.endswith("\n")
              and len(parts) == 3 and ISO.match(parts[0])
              and parts[1] == "127.0.0.1"
              and parts[2] == "<134>Sep 21 10:00:00 ER8411 test: hello world")
        check("line format: recvtime TAB src TAB raw", ok, repr(content[:200]))

        # 3. multi-record / injection: CR/LF inside a datagram splits into
        #    separate lines, each re-prefixed (attribution can't be forged)
        send(b"<134>injected\r\nFAKE<134>evil")
        time.sleep(0.4)
        lines = read_lines()
        ok = (len(lines) == 3
              and all(ISO.match(l.split("\t")[0]) for l in lines[1:])
              and all(l.split("\t")[1] == "127.0.0.1" for l in lines[1:])
              and lines[1].split("\t")[2] == "<134>injected"
              and lines[2].split("\t")[2] == "FAKE<134>evil")
        check("embedded CR/LF splits into prefixed records (no forged lines)",
              ok, "%d lines" % len(lines))

        # 4. malformed bytes + NUL padding tolerated
        before = len(read_lines())
        send(b"\xff\xfe\x00binary garbage\x00\x00")
        time.sleep(0.4)
        after = len(read_lines())
        check("malformed/NUL datagram recorded once", after == before + 1)

        # 5. empty datagram ignored
        before = len(read_lines())
        send(b"")
        time.sleep(0.3)
        after = len(read_lines())
        check("empty datagram ignored", before == after)

        # 6. trim edge case: single oversized line is left alone
        edge_path = os.path.join(tmp, "edge.log")
        with open(edge_path, "wb") as f:
            f.write(b"x" * 100000)
        rec.trim_file(edge_path, cap_bytes=50000, keep_pct=90)
        check("trim leaves oversized single line untouched",
              os.path.getsize(edge_path) == 100000)

        # 7. trim stress: cap is 0.05 MB, push ~900 KB through
        for i in range(3000):
            send(b"<134>Sep 21 10:00:00 ER8411 test: seq-%06d " % i + b"x" * 250)
            if i % 500 == 0:
                time.sleep(0.05)
        time.sleep(2.5)  # let the 1s idle size-check fire
        size = os.path.getsize(logfile)
        data = open(logfile, "rb").read()
        cap = int(0.05 * 1024 * 1024)
        ends_nl = data.endswith(b"\n")
        first_ok = all(ISO.match(l.split(b"\t")[0].decode("ascii", "replace"))
                       for l in data.splitlines()[:5])
        check("trim: file kept at/below ~cap", size <= cap + 2000,
              "size=%d cap=%d" % (size, cap))
        check("trim: whole lines only, each starts with timestamp",
              ends_nl and data.count(b"\n") > 0 and first_ok)
        check("trim: newest kept, oldest rolled off",
              b"seq-002999" in data and b"seq-000000" not in data)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    # ---- condenser tests -------------------------------------------------------
    def alive(p):
        return p.poll() is None

    def load_cond(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)

    def start_rx(port, cfile, extra=()):
        rxlog = os.path.join(tmp, "rx%d.log" % port)
        p = subprocess.Popen(
            [sys.executable, RECEIVER, "--port", str(port), "--allow", "127.0.0.1",
             "--log-file", rxlog, "--condense-file", cfile] + list(extra),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check("receiver binds port %d" % port, wait_port_taken(port))
        return p

    def stop_rx(p):
        p.terminate()
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            p.kill()

    def send_port(payload, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(payload, ("127.0.0.1", port))
        s.close()

    def flow_payload(spt, dst="10.0.0.2", dpt=53, seq="1.1"):
        return (b"<6>Sep 21 10:00:00 testh [" + seq.encode() + b"] AP MAC=aa:bb:cc:dd:ee:ff "
                b"IP SRC=10.0.0.1 IP DST=" + dst.encode() + b" IP proto=17 SPT="
                + str(spt).encode() + b" DPT=" + str(dpt).encode())

    # 8. dedup: SPT folded into samples, occurrences bounded
    c1 = os.path.join(tmp, "cond1.json")
    rx = start_rx(5152, c1, ["--condense-every", "1", "--occurrences", "3"])
    try:
        for i in range(5):
            send_port(flow_payload(1110 + i, seq="%d.1" % i), 5152)
        send_port(flow_payload(9999, dst="10.0.0.9", dpt=80, seq="9.9"), 5152)
        send_port(b"<134>Sep 21 10:00:00 testh [179.1] DoS attack: LAND from 10.0.0.9 port 1234", 5152)
        send_port(b"<134>Sep 21 10:00:00 testh [180.2] DoS attack: LAND from 10.0.0.9 port 1234", 5152)
        time.sleep(2.5)
        st = load_cond(c1)
        flows = [v for v in st.values() if v.get("type") == "flow"]
        msgs = [v for v in st.values() if v.get("type") == "msg"]
        fa = [v for v in flows if v.get("dst") == "10.0.0.2" and v.get("dpt") == 53]
        ok = (len(flows) == 2 and len(msgs) == 1 and bool(fa)
              and fa[0]["count"] == 5 and len(fa[0]["occurrences"]) == 3
              and fa[0]["spt_sample"] == 1114 and msgs[0]["count"] == 2)
        check("condenser: flows dedup by (src,dst,proto,dpt); SPT sampled; occurrences bounded",
              ok, "flows=%d msgs=%d" % (len(flows), len(msgs)))
    finally:
        stop_rx(rx)

    # 9. tallies survive restart (marker catch-up, no double count)
    rx = start_rx(5152, c1, ["--condense-every", "1"])
    try:
        for i in range(3):
            send_port(flow_payload(2220 + i), 5152)
        time.sleep(2.5)
        st = load_cond(c1)
        fa = [v for v in st.values() if v.get("type") == "flow"
              and v.get("dst") == "10.0.0.2" and v.get("dpt") == 53]
        check("condenser: tallies survive receiver restart",
              bool(fa) and fa[0]["count"] == 8,
              "count=%s" % (fa[0]["count"] if fa else "missing"))
    finally:
        stop_rx(rx)

    # 10. --condense-max-keys bounds state (stalest evicted)
    c2 = os.path.join(tmp, "cond2.json")
    rx = start_rx(5153, c2, ["--condense-every", "1", "--condense-max-keys", "3"])
    try:
        for i in range(6):
            send_port(flow_payload(1, dst="10.0.1.%d" % i), 5153)
        time.sleep(2.5)
        st = load_cond(c2)
        check("condenser: --condense-max-keys bounds RAM state",
              len([k for k in st if k != "_meta"]) <= 3,
              "keys=%d" % len([k for k in st if k != "_meta"]))
    finally:
        stop_rx(rx)

    # 11. size-cap eviction; ingestion unaffected
    c3 = os.path.join(tmp, "cond3.json")
    rxlog4 = os.path.join(tmp, "rx5154.log")
    rx = subprocess.Popen(
        [sys.executable, RECEIVER, "--port", "5154", "--allow", "127.0.0.1",
         "--log-file", rxlog4, "--condense-file", c3,
         "--condense-every", "1", "--condense-max-mb", "0.000001"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("receiver binds port 5154", wait_port_taken(5154))
        send_port(flow_payload(1), 5154)
        send_port(flow_payload(2), 5154)
        time.sleep(2.0)
        send_port(flow_payload(3), 5154)
        time.sleep(2.0)
        st = load_cond(c3)
        n_raw = len(open(rxlog4, encoding="utf-8").read().splitlines())
        check("condenser: size cap evicts stalest, ingestion unaffected",
              alive(rx) and n_raw == 3 and os.path.getsize(c3) < 2000
              and len([k for k in st if k != "_meta"]) == 0,
              "alive=%s raw=%d size=%d" % (alive(rx), n_raw, os.path.getsize(c3)))
    finally:
        stop_rx(rx)

    # 12. armor: broken condense path never affects ingestion
    c4 = os.path.join(tmp, "no_such_dir", "c<.json")
    rxlog5 = os.path.join(tmp, "rx5155.log")
    rx = subprocess.Popen(
        [sys.executable, RECEIVER, "--port", "5155", "--allow", "127.0.0.1",
         "--log-file", rxlog5, "--condense-file", c4, "--condense-every", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("receiver binds port 5155", wait_port_taken(5155))
        send_port(flow_payload(1), 5155)
        time.sleep(2.0)
        send_port(flow_payload(2), 5155)
        time.sleep(1.0)
        n_raw = len(open(rxlog5, encoding="utf-8").read().splitlines())
        check("condenser: condensation failures never affect raw ingestion",
              alive(rx) and n_raw == 2, "alive=%s raw=%d" % (alive(rx), n_raw))
    finally:
        stop_rx(rx)

    # 13. replay CLI: marker-resumed folding
    raw6 = os.path.join(tmp, "replay.log")
    c5 = os.path.join(tmp, "cond5.json")
    with open(raw6, "w", encoding="utf-8") as f:
        f.write("2026-09-21T10:00:00.000-10:00\t127.0.0.1\t<6>Sep 21 10:00:00 h [1.1] IP SRC=10.0.0.1 IP DST=10.0.0.2 IP proto=17 SPT=1 DPT=53\n")
        f.write("2026-09-21T10:00:01.000-10:00\t127.0.0.1\t<6>Sep 21 10:00:01 h [1.2] IP SRC=10.0.0.1 IP DST=10.0.0.2 IP proto=17 SPT=2 DPT=53\n")
        f.write("2026-09-21T10:00:02.000-10:00\t127.0.0.1\t<134>system message alpha\n")
    r = subprocess.run([sys.executable, CONDENSER, "--replay", raw6, "--condense-file", c5],
                        capture_output=True, text=True)
    st = load_cond(c5) if os.path.exists(c5) else {}
    ok = (r.returncode == 0 and "folded 3" in r.stdout
          and any(v.get("type") == "flow" and v.get("count") == 2 for v in st.values()))
    check("replay: folds raw backlog into tallies", ok,
          (r.stdout.strip() + " " + r.stderr.strip())[:200])

    r = subprocess.run([sys.executable, CONDENSER, "--replay", raw6, "--condense-file", c5],
                        capture_output=True, text=True)
    check("replay: re-run with no new lines folds 0",
          r.returncode == 0 and "folded 0" in r.stdout, r.stdout.strip())

    with open(raw6, "a", encoding="utf-8") as f:
        f.write("2026-09-21T10:00:03.000-10:00\t127.0.0.1\t<6>Sep 21 10:00:03 h [1.3] IP SRC=10.0.0.1 IP DST=10.0.0.2 IP proto=17 SPT=3 DPT=53\n")
        f.write("2026-09-21T10:00:04.000-10:00\t127.0.0.1\t<134>system message beta\n")
    r = subprocess.run([sys.executable, CONDENSER, "--replay", raw6, "--condense-file", c5],
                        capture_output=True, text=True)
    st = load_cond(c5)
    fa = [v for v in st.values() if v.get("type") == "flow"]
    check("replay: marker resumes incremental folding",
          r.returncode == 0 and "folded 2" in r.stdout and bool(fa) and fa[0]["count"] == 3,
          r.stdout.strip())

    raw7 = os.path.join(tmp, "replay2.log")
    with open(raw7, "w", encoding="utf-8") as f:
        f.write("2026-09-21T10:00:05.000-10:00\t127.0.0.1\t<134>system message gamma\n")
    r = subprocess.run([sys.executable, CONDENSER, "--replay", raw7, "--condense-file", c5],
                        capture_output=True, text=True)
    check("replay: refuses when marker line was trimmed", r.returncode == 2,
          "rc=%d" % r.returncode)
    r = subprocess.run([sys.executable, CONDENSER, "--replay", raw7,
                        "--condense-file", c5, "--force"],
                        capture_output=True, text=True)
    st = load_cond(c5)
    check("replay: --force folds whole current file",
          r.returncode == 0
          and any(v.get("template") == "system message gamma" for v in st.values()),
          r.stdout.strip())

    # 14. catch-up marker gone: tallying must continue (not disable)
    c6 = os.path.join(tmp, "cond6.json")
    with open(c6, "w", encoding="utf-8") as f:
        json.dump({"_meta": {"records": 1, "keys": 1, "replay_last_hash": "deadbeef"},
                   "msg|9.9.9.9|1|old": {"type": "msg", "from": "9.9.9.9", "sev": 1,
                                         "template": "old", "count": 1, "first": "x",
                                         "last": "y", "occurrences": []}}, f)
    rx = start_rx(5156, c6, ["--condense-every", "1"])
    try:
        send_port(flow_payload(1, dst="10.9.9.9"), 5156)
        time.sleep(2.5)
        st = load_cond(c6)
        flows = [v for v in st.values() if v.get("type") == "flow"]
        check("condenser: missing catch-up marker skips fold but keeps tallying",
              bool(flows) and flows[0]["count"] == 1, "flows=%d" % len(flows))
    finally:
        stop_rx(rx)

    # 15. locked condense file: flush failures never affect ingestion;
    #     tallies persist once the lock is released
    c7 = os.path.join(tmp, "cond7.json")
    with open(c7, "w", encoding="utf-8") as f:
        json.dump({}, f)
    rxlog7 = os.path.join(tmp, "rx5157.log")
    rx = subprocess.Popen(
        [sys.executable, RECEIVER, "--port", "5157", "--allow", "127.0.0.1",
         "--log-file", rxlog7, "--condense-file", c7, "--condense-every", "1"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        check("receiver binds port 5157", wait_port_taken(5157))
        send_port(flow_payload(1), 5157)
        lock = open(c7, "r", encoding="utf-8")  # held handle: os.replace will fail
        time.sleep(2.5)
        send_port(flow_payload(2), 5157)
        time.sleep(1.5)
        n_raw = len(open(rxlog7, encoding="utf-8").read().splitlines())
        check("condenser: locked-file flush failures never affect ingestion",
              alive(rx) and n_raw == 2, "alive=%s raw=%d" % (alive(rx), n_raw))
        lock.close()
        time.sleep(2.0)
        st = load_cond(c7)
        flows = [v for v in st.values() if v.get("type") == "flow"]
        check("condenser: tallies persist once the lock is released",
              bool(flows) and flows[0]["count"] == 2, "flows=%d" % len(flows))
    finally:
        stop_rx(rx)

    # 16. viz server: serves the UI page + parsed API
    cviz_log = os.path.join(tmp, "viz.log")
    cviz_cond = os.path.join(tmp, "vizcond.json")
    with open(cviz_log, "w", encoding="utf-8") as f:
        f.write("2026-09-21T10:00:00.000-10:00\t127.0.0.1\t<6>Sep 21 10:00:00 h [1.1] IP SRC=10.0.0.1 IP DST=1.1.1.1 IP proto=17 SPT=1 DPT=53\n")
        f.write("2026-09-21T10:00:01.000-10:00\t127.0.0.1\t<134>alert thing happened\n")
        f.write("2026-09-21T10:00:02.000-10:00\t127.0.0.1\t<6>Sep 21 10:00:02 h [1.2] IP SRC=8.8.8.8 IP DST=10.0.0.5 IP proto=6 SPT=443 DPT=5555\n")
    with open(cviz_cond, "w", encoding="utf-8") as f:
        json.dump({"_meta": {"records": 2, "keys": 1},
                   "flow|10.0.0.1|10.0.0.2|17|53":
                       {"type": "flow", "src": "10.0.0.1", "dst": "10.0.0.2",
                        "proto": 17, "dpt": 53, "count": 2,
                        "first": "2026-09-21T10:00:00.000-10:00",
                        "last": "2026-09-21T10:00:01.000-10:00",
                        "occurrences": ["2026-09-21T10:00:01.000-10:00"]}}, f)
    # pick a free port dynamically (immune to port squatters)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    vport = probe.getsockname()[1]
    probe.close()
    vz = subprocess.Popen(
        [sys.executable, VIZ, "--port", str(vport),
         "--condense-file", cviz_cond, "--log-file", cviz_log, "--raw-tail", "100"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        page = None
        api = None
        end = time.time() + 10
        base = "http://127.0.0.1:%d" % vport
        while time.time() < end:
            try:
                page = urllib.request.urlopen(base + "/", timeout=2).read().decode("utf-8", "replace")
                api = json.load(urllib.request.urlopen(base + "/api/data", timeout=2))
                break
            except OSError:
                time.sleep(0.3)
        ok = (page is not None and "<canvas" in page
              and "selYS" in page and "chkFlipY" in page and "chkDirOut" in page
              and "fPortNot" in page and "btnHelp" in page and 'id="brush"' in page
              and api is not None
              and len(api.get("entries", [])) == 1
              and len(api.get("raw", [])) == 3
              and api["raw"][0].get("dpt") == 53
              and api["raw"][0].get("dir") == "outbound"
              and api["raw"][1].get("type") == "msg" and api["raw"][1].get("dir") == "other"
              and api["raw"][2].get("dir") == "inbound"
              and api["entries"][0].get("dir") == "internal")
        check("viz: serves UI page (incl. new controls) + parsed API with directions",
              ok, "page=%s api=%s" % (page is not None, api is not None))
    finally:
        vz.terminate()
        try:
            vz.wait(timeout=5)
        except subprocess.TimeoutExpired:
            vz.kill()

    # 17. RFC1918 direction classification (unit)
    import omada_viz as ov
    cases = [
        (("192.168.0.1", "10.0.0.5"), "internal"),
        (("10.0.0.1", "10.1.2.3"), "internal"),
        (("172.16.4.5", "172.31.9.9"), "internal"),
        (("192.168.0.50", "1.1.1.1"), "outbound"),
        (("192.168.0.10", "224.0.0.251"), "outbound"),
        (("8.8.8.8", "192.168.0.5"), "inbound"),
        (("198.51.100.7", "192.168.0.50"), "inbound"),
        (("8.8.8.8", "1.1.1.1"), "other"),
        ((None, "1.1.1.1"), "other"),
        (("192.168.0.1", None), "other"),
    ]
    bad = ["%s->%s = %s (want %s)" % (s, d, ov.direction_of(s, d), want)
           for (s, d), want in cases if ov.direction_of(s, d) != want]
    check("viz: RFC1918 direction classification (internal/outbound/inbound/other)",
          not bad, "; ".join(bad))

    print()
    if failures:
        print("FAILED: " + ", ".join(failures))
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
