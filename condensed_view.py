#!/usr/bin/env python3
"""Query tool for the condensed syslog tallies (condensed.json).

Examples:
    python condensed_view.py                          # top 20 tallies by count
    python condensed_view.py --top 50 --type flow
    python condensed_view.py --src 192.168.0.10 --dst 1.1.1.1
    python condensed_view.py --type msg --stale 7     # dormant 7+ days
    python condensed_view.py --json > tallies.json
"""

import argparse
import json
import os
import sys
from datetime import datetime, timedelta

DEFAULT_FILE = os.path.join(os.environ.get("LOCALAPPDATA")
                            or os.path.expanduser(r"~\AppData\Local"),
                            "OmadaSyslog", "condensed.json")
PROTO = {1: "icmp", 2: "igmp", 6: "tcp", 17: "udp", 47: "gre", 50: "esp"}


def parse_args():
    p = argparse.ArgumentParser(prog="condensed_view",
                                description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--condense-file", default=DEFAULT_FILE,
                   help="tallies file (default: %(default)s)")
    p.add_argument("--top", type=int, default=20,
                   help="show top N by count (default: %(default)s)")
    p.add_argument("--type", choices=["flow", "msg"], default=None)
    p.add_argument("--src", default=None, help="filter: source or sender (substring)")
    p.add_argument("--dst", default=None, help="filter: destination (substring)")
    p.add_argument("--text", default=None,
                   help="filter: message/template substring (case-insensitive)")
    p.add_argument("--since", default=None,
                   help="only tallies last seen at/after this (ISO date/time prefix)")
    p.add_argument("--stale", type=float, default=None, metavar="DAYS",
                   help="only tallies dormant for >= DAYS")
    p.add_argument("--min-count", type=int, default=None)
    p.add_argument("--json", action="store_true", help="output matching entries as JSON")
    p.add_argument("--meta", action="store_true", help="also print the store meta header")
    return p.parse_args()


def main():
    a = parse_args()
    try:
        with open(a.condense_file, encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError) as e:
        print("cannot read %s: %s" % (a.condense_file, e), file=sys.stderr)
        return 1
    meta = state.pop("_meta", None)
    if a.meta and meta:
        print(json.dumps(meta, indent=2))

    def keep(v):
        if a.type and v.get("type") != a.type:
            return False
        if a.src and a.src not in str(v.get("src") or v.get("from") or ""):
            return False
        if a.dst and a.dst not in str(v.get("dst") or ""):
            return False
        if a.text and a.text.lower() not in str(v.get("template") or "").lower():
            return False
        if a.min_count is not None and v.get("count", 0) < a.min_count:
            return False
        if a.since and str(v.get("last", "")) < a.since:
            return False
        if a.stale is not None:
            try:
                last = datetime.fromisoformat(v.get("last"))
            except (TypeError, ValueError):
                return False
            if datetime.now().astimezone() - last < timedelta(days=a.stale):
                return False
        return True

    entries = [v for v in state.values() if keep(v)]
    entries.sort(key=lambda v: v.get("count", 0), reverse=True)
    if a.top:
        entries = entries[:a.top]
    if a.json:
        print(json.dumps(entries, indent=2))
        return 0
    for v in entries:
        if v.get("type") == "flow":
            print("%8d  %-15s -> %-15s %5s/%-5s first=%s last=%s" % (
                v.get("count", 0), v.get("src"), v.get("dst"),
                PROTO.get(v.get("proto"), v.get("proto")),
                v.get("dpt") if v.get("dpt") is not None else "-",
                v.get("first", "?"), v.get("last", "?")))
        else:
            print("%8d  [sev=%s] %-15s %s" % (
                v.get("count", 0),
                v.get("sev") if v.get("sev") is not None else "-",
                v.get("from", "?"), str(v.get("template"))[:100]))
    print("\n(%d entries shown)" % len(entries))
    return 0


if __name__ == "__main__":
    sys.exit(main())
