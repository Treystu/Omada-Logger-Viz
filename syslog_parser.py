#!/usr/bin/env python3
"""Offline pretty-printer / filter for the Omada syslog receiver's log file.

Log lines look like:
    <recv-time ISO8601>\t<source IP>\t<raw syslog message>

Examples:
    python syslog_parser.py                          # pretty-print everything
    python syslog_parser.py --sev err                # only severity err or worse
    python syslog_parser.py --src 192.168.0.1 -n 100 # last 100 lines from firewall
    python syslog_parser.py --text "dos attack" --raw
"""

import argparse
import os
import re
import sys

DEFAULT_LOG = os.path.join(os.environ.get("LOCALAPPDATA")
                           or os.path.expanduser(r"~\AppData\Local"),
                           "OmadaSyslog", "firewall.log")

FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
              "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock"]
SEVERITIES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]

LINE_RE = re.compile(r"^(?P<ts>\S+)\t(?P<src>\S+)\t(?P<raw>.*)$")
PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<rest>.*)$")


def parse_args():
    p = argparse.ArgumentParser(
        prog="syslog_parser",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--log-file", default=DEFAULT_LOG,
                   help="log file to read (default: %(default)s)")
    p.add_argument("--sev", metavar="NAME|0-7", default=None,
                   help="show only this severity and worse (e.g. err)")
    p.add_argument("--fac", default=None,
                   help="filter by facility (substring, e.g. kern)")
    p.add_argument("--src", default=None,
                   help="filter by source IP (substring)")
    p.add_argument("--text", default=None,
                   help="case-insensitive substring filter on the message")
    p.add_argument("-n", "--tail", type=int, default=None,
                   help="show only the last N matching lines")
    p.add_argument("--raw", action="store_true",
                   help="print matching lines verbatim instead of pretty format")
    return p.parse_args()


def main():
    a = parse_args()
    sev_max = None
    if a.sev is not None:
        s = a.sev.strip().lower()
        sev_max = SEVERITIES.index(s) if s in SEVERITIES else int(s)

    out = []
    with open(a.log_file, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.rstrip("\n")
            m = LINE_RE.match(line)
            if m:
                ts, src, raw = m.group("ts"), m.group("src"), m.group("raw")
            else:
                ts, src, raw = "-", "-", line

            fac = sev = None
            msg = raw
            pm = PRI_RE.match(raw)
            if pm:
                pri = int(pm.group("pri"))
                if pri <= 191:
                    fac = FACILITIES[pri // 8]
                    sev = pri % 8
                    msg = pm.group("rest")

            if sev_max is not None and (sev is None or sev > sev_max):
                continue
            if a.fac and (fac is None or a.fac.lower() not in fac):
                continue
            if a.src and a.src not in src:
                continue
            if a.text and a.text.lower() not in msg.lower():
                continue

            if a.raw:
                out.append(line)
            else:
                level = "%s.%s" % (fac, SEVERITIES[sev]) if sev is not None else "-"
                out.append("%s  %-15s  %-14s  %s" % (ts, src, level, msg))

    if a.tail is not None:
        out = out[-a.tail:]
    if out:
        sys.stdout.write("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
