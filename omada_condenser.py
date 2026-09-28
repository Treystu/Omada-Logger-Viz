#!/usr/bin/env python3
"""Condenser for the Omada syslog receiver - tallies records at ingestion time.

Folds repetitive syslog records into aggregated tallies so the condensed
store keeps counts and recency instead of every raw record:

- Flow records (IP SRC=.. IP DST=.. IP proto=.. [SPT=..] [DPT=..]) tally on
  the key (src, dst, proto, dpt). The ephemeral source port is stored as a
  sample only, so repeated connections fold into a single entry.
- Other messages tally on (sender, severity, message with the [epoch.seq]
  tag masked). Identical events fold into a single entry.
- Each entry keeps: count, first/last seen, and the N most recent duplicate
  occurrence timestamps (default 20).

State is a single JSON document, atomically rewritten on flush
(temp file + os.replace). Retention: when the serialized state exceeds its
size cap, entries with the oldest last-seen time are evicted (stalest first).
The number of distinct keys in RAM is hard-bounded too. Tallies survive
restarts: the state is loaded at startup.

Exactly-once crash recovery: every flush persists the hash of the last raw
line whose record is reflected in the tallies. On startup the receiver
"folds" raw-log lines that come after that marker, so records lost from
memory by a crash are recovered exactly once (see catch_up()).

Standalone use:
    python omada_condenser.py --replay [rawlog]   # fold raw backlog into tallies
    python omada_condenser.py --status            # print store summary
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from datetime import datetime

_LOCAL_APPDATA = (os.environ.get("LOCALAPPDATA")
                  or os.path.expanduser(r"~\AppData\Local"))
DEFAULT_RAW_LOG = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "firewall.log")
DEFAULT_CONDENSED = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "condensed.json")
DEFAULT_MAX_MB = 50.0
DEFAULT_MAX_KEYS = 100000
DEFAULT_OCCURRENCES = 20

FLOW_RE = re.compile(r"IP SRC=(\S+) IP DST=(\S+) IP proto=(\d+)(?: SPT=(\d+))?(?: DPT=(\d+))?")
AP_RE = re.compile(r"AP MAC=(\S+)")
PRI_RE = re.compile(r"^<(\d{1,3})>")
EPOCH_RE = re.compile(r"\[\d+\.\d+\]")


class Condenser:
    """In-memory tally store with atomic JSON persistence."""

    def __init__(self, path, max_bytes, max_keys=DEFAULT_MAX_KEYS,
                 occurrences=DEFAULT_OCCURRENCES):
        self.path = path
        self.max_bytes = max_bytes
        self.max_keys = max_keys
        self.occurrences = occurrences
        self.state = {}
        self.total = 0
        self.replay_marker = None   # persisted: hash of last raw line folded/tallied
        self.ingest_marker = None   # runtime: hash of last raw line ingested live
        self.dirty = False
        self.last_flush = time.time()
        self._load()

    # -- persistence ---------------------------------------------------------

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                meta = loaded.pop("_meta", {})
                self.state = {k: v for k, v in loaded.items() if isinstance(v, dict)}
                self.total = int(meta.get("records", 0))
                self.replay_marker = meta.get("replay_last_hash")
        except (OSError, ValueError):
            self.state = {}

    def flush(self):
        """Atomically persist the tally state (no-op when clean). Updates
        last_flush up front so a failed attempt (locked file etc.) throttles
        retries to once per interval instead of once per packet."""
        self.last_flush = time.time()
        if not self.dirty:
            return False
        marker = self.ingest_marker or self.replay_marker
        self.state["_meta"] = {
            "records": self.total,
            "keys": len(self.state),
            "last_flush": datetime.now().astimezone().isoformat(timespec="seconds"),
            "replay_last_hash": marker,
        }
        try:
            data = json.dumps(self.state, separators=(",", ":"), ensure_ascii=False)
            if len(data.encode("utf-8")) > self.max_bytes:
                self._evict()
                data = json.dumps(self.state, separators=(",", ":"), ensure_ascii=False)
            dirname = os.path.dirname(self.path) or "."
            fd, tmp = tempfile.mkstemp(dir=dirname, prefix=".cond-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(data)
                os.replace(tmp, self.path)
            except OSError:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        finally:
            self.state.pop("_meta", None)
        self.dirty = False
        self.last_flush = time.time()
        return True

    def _evict(self):
        """Drop stalest-first (oldest last-seen) entries until <= 90% of cap."""
        target = int(self.max_bytes * 0.9)
        items = [(k, v) for k, v in self.state.items() if k != "_meta"]
        if not items:
            return
        sizes = {k: len(json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
                 for k, v in items}
        total = sum(sizes.values())
        if total <= target:
            return
        items.sort(key=lambda kv: kv[1].get("last", ""))
        for k, _ in items:
            if total <= target:
                break
            total -= sizes[k]
            del self.state[k]

    def _ensure_capacity(self):
        """Hard RAM bound: when at max_keys, evict the stalest ~5%."""
        if len(self.state) < self.max_keys:
            return
        entries = sorted(self.state.items(), key=lambda kv: kv[1].get("last", ""))
        for k, _ in entries[:max(1, len(entries) // 20)]:
            del self.state[k]

    # -- ingestion -----------------------------------------------------------

    def note_raw(self, body):
        """Record the hash of the last raw log line (sans newline) ingested."""
        self.ingest_marker = hashlib.sha1(body.encode("utf-8", "replace")).hexdigest()

    def add(self, recv_time, src_ip, raw):
        m = FLOW_RE.search(raw)
        if m:
            self._add_flow(recv_time, m, raw)
        else:
            self._add_msg(recv_time, src_ip, raw)

    def _bump(self, e, recv_time):
        e["count"] += 1
        e["last"] = recv_time
        occ = e["occurrences"]
        occ.append(recv_time)
        if len(occ) > self.occurrences:
            del occ[:len(occ) - self.occurrences]
        self.total += 1
        self.dirty = True

    def _add_flow(self, recv_time, m, raw):
        key = "flow|%s|%s|%s|%s" % (m.group(1), m.group(2), m.group(3), m.group(5) or "")
        e = self.state.get(key)
        if e is None:
            self._ensure_capacity()
            e = {"type": "flow", "src": m.group(1), "dst": m.group(2),
                 "proto": int(m.group(3)), "dpt": int(m.group(5)) if m.group(5) else None,
                 "count": 0, "first": recv_time, "last": recv_time, "occurrences": []}
            self.state[key] = e
        if m.group(4):
            e["spt_sample"] = int(m.group(4))
        ap = AP_RE.search(raw)
        if ap:
            e["ap"] = ap.group(1)
        self._bump(e, recv_time)

    def _add_msg(self, recv_time, src_ip, raw):
        body = raw
        sev = None
        pm = PRI_RE.match(raw)
        if pm and int(pm.group(1)) <= 191:
            sev = int(pm.group(1)) % 8
            body = PRI_RE.sub("", raw, count=1)
        template = EPOCH_RE.sub("[...]", body)
        key = "msg|%s|%s|%s" % (src_ip, sev if sev is not None else "-", template)
        e = self.state.get(key)
        if e is None:
            self._ensure_capacity()
            e = {"type": "msg", "from": src_ip, "sev": sev, "template": template,
                 "count": 0, "first": recv_time, "last": recv_time,
                 "occurrences": [], "sample": raw}
            self.state[key] = e
        self._bump(e, recv_time)

    # -- crash recovery / backlog -------------------------------------------

    def catch_up(self, raw_path, force=False):
        """Fold raw-log lines after the persisted marker into the tallies.
        Returns the number of lines folded. Raises RuntimeError if the marker
        line is no longer present (trimmed away) unless force=True."""
        try:
            with open(raw_path, encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\n") for l in f]
        except FileNotFoundError:
            return 0
        start = 0
        if self.replay_marker:
            start = None
            for i, l in enumerate(lines):
                if hashlib.sha1(l.encode("utf-8", "replace")).hexdigest() == self.replay_marker:
                    start = i + 1
                    break
            if start is None:
                if not force:
                    raise RuntimeError(
                        "replay marker line no longer present in %s" % raw_path)
                start = 0
        folded = 0
        last = None
        for l in lines[start:]:
            parts = l.split("\t", 2)
            if len(parts) != 3 or not parts[2]:
                continue
            self.add(parts[0], parts[1], parts[2])
            folded += 1
            last = l
        if folded and last is not None:
            self.replay_marker = hashlib.sha1(last.encode("utf-8", "replace")).hexdigest()
        return folded


# -- standalone CLI ------------------------------------------------------------

def replay_cmd(a):
    cond = Condenser(a.condense_file, int(a.condense_max_mb * 1024 * 1024),
                     a.condense_max_keys, a.occurrences)
    try:
        n = cond.catch_up(a.replay, force=a.force)
    except FileNotFoundError:
        print("raw log not found: %s" % a.replay)
        return 1
    except RuntimeError as e:
        print("%s" % e)
        print("Re-run with --force to fold the entire current file "
              "(may double-count already-tallied lines).")
        return 2
    if n:
        cond.flush()
    print("replay: folded %d line(s); %d records across %d keys"
          % (n, cond.total, len(cond.state)))
    print("note: if the receiver is running, its next flush will overwrite this "
          "file - stop the receiver first when replaying.")
    return 0


def status_cmd(a):
    cond = Condenser(a.condense_file, int(a.condense_max_mb * 1024 * 1024),
                     a.condense_max_keys, a.occurrences)
    print("store: %s" % a.condense_file)
    print("records=%d  keys=%d  marker=%s"
          % (cond.total, len(cond.state), cond.replay_marker or "-"))
    for v in sorted(cond.state.values(), key=lambda v: v.get("count", 0), reverse=True)[:10]:
        if v.get("type") == "flow":
            print("%8d  %s -> %s proto=%s dpt=%s" % (v["count"], v["src"], v["dst"],
                                                    v["proto"], v.get("dpt")))
        else:
            print("%8d  [sev=%s] %s" % (v["count"], v.get("sev"),
                                        str(v.get("template"))[:90]))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="omada_condenser", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--replay", nargs="?", const=DEFAULT_RAW_LOG, default=None,
                   metavar="RAW_LOG", help="fold raw-log lines into the condensed "
                   "store (marker-resumable; default log: %s)" % DEFAULT_RAW_LOG)
    p.add_argument("--force", action="store_true",
                   help="with --replay: fold the whole file even if the marker line is gone")
    p.add_argument("--status", action="store_true", help="print store summary + top tallies")
    p.add_argument("--condense-file", default=DEFAULT_CONDENSED,
                   help="tallies file (default: %(default)s)")
    p.add_argument("--condense-max-mb", type=float, default=DEFAULT_MAX_MB,
                   help="size cap in MB (default: %(default)s)")
    p.add_argument("--condense-max-keys", type=int, default=DEFAULT_MAX_KEYS,
                   help="max distinct tally keys (default: %(default)s)")
    p.add_argument("--occurrences", type=int, default=DEFAULT_OCCURRENCES,
                   help="recent occurrence timestamps per entry (default: %(default)s)")
    a = p.parse_args(argv)
    if a.replay:
        return replay_cmd(a)
    if a.status:
        return status_cmd(a)
    p.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
