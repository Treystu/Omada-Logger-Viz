#!/usr/bin/env python3
"""Omada syslog receiver - a minimal UDP syslog collector for TP-Link Omada remote logging.

Listens on UDP 514 (default), accepts datagrams from allow-listed addresses
(default: the 192.168.0.0/24 LAN), stamps each message with receive time and
source IP, and appends the raw payload to a single log file. When the file
exceeds the size cap (default 50 MB) the oldest whole lines are trimmed away,
so the file stays around the cap - newest events always kept, oldest rolled
off first.

Every record is also folded into aggregated tallies (condensed.json, its own
50 MB cap, restart-safe) so repeated flows/events can be reviewed as counts
instead of thousands of raw lines - see omada_condenser.py. Disable with
--no-condense.

Built to run headless (Task Scheduler boot task via pythonw.exe) with zero
third-party dependencies (Python 3 stdlib only).

Line format:
    <receive time, ISO8601 with local offset>\t<source IP>\t<raw message>

Examples:
    python omada_syslog.py                                    # all defaults
    python omada_syslog.py --port 514 --max-mb 50 --verbose
    python omada_syslog.py --allow 192.168.0.0/24 --allow 10.0.0.5
"""

import argparse
import ipaddress
import os
import re
import socket
import sys
import tempfile
import time
from datetime import datetime

DEFAULT_BIND = "0.0.0.0"
DEFAULT_PORT = 514
DEFAULT_ALLOW = ["192.168.0.0/24"]
_LOCAL_APPDATA = (os.environ.get("LOCALAPPDATA")
                  or os.path.join(os.path.expanduser("~"), "AppData", "Local"))
DEFAULT_LOG_FILE = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "firewall.log")
DEFAULT_MAX_MB = 50.0
DEFAULT_KEEP_PCT = 90.0
DEFAULT_CONDENSED_FILE = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "condensed.json")
DEFAULT_CONDENSE_MAX_MB = 50.0
DEFAULT_CONDENSE_EVERY = 60
DEFAULT_CONDENSE_MAX_KEYS = 100000
DEFAULT_OCCURRENCES = 20

RCVBUF_BYTES = 1 << 20           # socket receive buffer: burst tolerance
SIZE_CHECK_BYTES = 256 * 1024    # check file size after this many written bytes
SIZE_CHECK_IDLE_S = 1.0          # ... or after this many idle seconds


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="omada_syslog",
        description="Minimal UDP syslog receiver for TP-Link Omada remote logging.",
        epilog="Defaults match a single Omada firewall on the 192.168.0.0/24 LAN; "
               "every default is overridable with the flags below.")
    p.add_argument("--bind", default=DEFAULT_BIND,
                   help="local address to listen on (default: %(default)s)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="UDP port (default: %(default)s)")
    p.add_argument("--allow", action="append", metavar="IP|CIDR", default=None,
                   help="authorized sender; repeatable, plain IP or CIDR "
                        "(default: %s; use 0.0.0.0/0 to accept everyone)"
                        % ", ".join(DEFAULT_ALLOW))
    p.add_argument("--log-file", default=DEFAULT_LOG_FILE,
                   help="log file (default: %(default)s)")
    p.add_argument("--max-mb", type=float, default=DEFAULT_MAX_MB,
                   help="size cap in MB before oldest lines are trimmed (default: %(default)s)")
    p.add_argument("--keep-pct", type=float, default=DEFAULT_KEEP_PCT,
                   help="after a trim, keep the newest N%% of the cap (default: %(default)s)")
    p.add_argument("--condense-file", default=DEFAULT_CONDENSED_FILE,
                   help="condensed tallies file (default: %(default)s)")
    p.add_argument("--condense-max-mb", type=float, default=DEFAULT_CONDENSE_MAX_MB,
                   help="size cap in MB for the condensed store (default: %(default)s)")
    p.add_argument("--condense-every", type=int, default=DEFAULT_CONDENSE_EVERY,
                   help="seconds between condensed-state flushes (default: %(default)s)")
    p.add_argument("--condense-max-keys", type=int, default=DEFAULT_CONDENSE_MAX_KEYS,
                   help="hard bound on distinct tally keys in RAM (default: %(default)s)")
    p.add_argument("--occurrences", type=int, default=DEFAULT_OCCURRENCES,
                   help="recent duplicate-occurrence timestamps kept per tally (default: %(default)s)")
    p.add_argument("--no-condense", action="store_true",
                   help="disable condensation (raw log only)")
    p.add_argument("--verbose", action="store_true",
                   help="echo received lines to stdout, dropped datagrams to stderr")
    args = p.parse_args(argv)
    if not 1 <= args.port <= 65535:
        p.error("port must be 1-65535")
    if args.max_mb <= 0:
        p.error("--max-mb must be positive")
    if not 1 <= args.keep_pct <= 100:
        p.error("--keep-pct must be 1-100")
    if args.condense_max_mb <= 0:
        p.error("--condense-max-mb must be positive")
    if args.condense_every < 1:
        p.error("--condense-every must be at least 1 second")
    if args.occurrences < 1:
        p.error("--occurrences must be at least 1")
    if args.condense_max_keys < 1:
        p.error("--condense-max-keys must be at least 1")
    if args.allow is None:
        args.allow = list(DEFAULT_ALLOW)
    return args


def build_allowlist(entries):
    nets = []
    for e in entries:
        nets.append(ipaddress.ip_network(e, strict=False))
    return nets


def is_allowed(src_ip, nets):
    try:
        addr = ipaddress.ip_address(src_ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def split_records(msg):
    """Split a datagram into individual records: Omada devices pack multiple
    flow records into one datagram separated by CR/LF. Each record becomes
    its own log line and gets the receive-time + source-IP prefix, so neither
    multi-record datagrams nor crafted payloads can forge attribution.
    NULs are stripped (some devices NUL-pad datagrams)."""
    msg = msg.replace("\x00", "")
    return [p for p in re.split(r"[\r\n]+", msg) if p]


def open_log(path):
    return open(path, "a", encoding="utf-8", newline="\n")


def trim_file(path, cap_bytes, keep_pct):
    """Atomically trim the oldest whole lines so the file is at most
    cap_bytes * keep_pct/100. Safe: temp file + os.replace; if the log is
    locked by another process, raises PermissionError and leaves it alone."""
    keep_target = int(cap_bytes * keep_pct / 100.0)
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except FileNotFoundError:
        return
    if len(data) <= keep_target:
        return
    cut = len(data) - keep_target
    nl = data.find(b"\n", cut)
    if nl < 0 or nl + 1 >= len(data):
        return  # no line boundary to cut on (e.g. one giant line): leave as-is
    kept = data[nl + 1:]
    dirname = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=dirname, prefix=".trim-", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(kept)
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def enforce_cap(log, path, cap_bytes, keep_pct):
    """Size-check + trim; returns the (possibly re-opened) log handle."""
    try:
        size = os.path.getsize(path)
    except OSError:
        return log
    try:
        hsize = os.fstat(log.fileno()).st_size
    except OSError:
        hsize = size
    if size < hsize:  # path was replaced/rotated externally: follow the new file
        log.close()
        return open_log(path)
    if size > cap_bytes:
        log.close()
        try:
            trim_file(path, cap_bytes, keep_pct)
        except OSError:
            pass  # locked by another process; retry next check
        return open_log(path)
    return log


def serve(args):
    nets = build_allowlist(args.allow)
    cap_bytes = int(args.max_mb * 1024 * 1024)
    log_dir = os.path.dirname(os.path.abspath(args.log_file))
    os.makedirs(log_dir, exist_ok=True)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RCVBUF_BYTES)
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # Windows: stop any other process from binding UDP 514 over us
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        sock.bind((args.bind, args.port))
    except OSError:
        sock.close()
        raise
    if args.verbose:
        print("listening on %s:%d  allow=%s  file=%s  cap=%s MB"
              % (args.bind, args.port, args.allow, args.log_file, args.max_mb),
              file=sys.stderr, flush=True)

    log = open_log(args.log_file)
    cond = None
    if not args.no_condense:
        try:
            from omada_condenser import Condenser
            cond = Condenser(args.condense_file,
                             int(args.condense_max_mb * 1024 * 1024),
                             args.condense_max_keys, args.occurrences)
        except Exception:
            if args.verbose:
                import traceback
                traceback.print_exc()
            cond = None
    if cond is not None:
        try:
            folded = cond.catch_up(args.log_file)  # recover un-tallied lines exactly once
        except Exception:
            folded = -1  # marker gone (trim+crash): accept the gap, keep tallying
            if args.verbose:
                import traceback
                traceback.print_exc()
        try:
            cond.flush()
        except Exception:
            pass
        if args.verbose:
            print("condenser resumed: %d keys / %d records (catch-up folded %s lines)"
                  % (len(cond.state), cond.total, folded), file=sys.stderr)
    pending = 0
    sock.settimeout(SIZE_CHECK_IDLE_S)
    try:
        while True:
            data = None
            addr = None
            try:
                data, addr = sock.recvfrom(65536)
            except socket.timeout:
                pass
            except OSError:
                time.sleep(0.05)  # transient Winsock error (e.g. WSAECONNRESET)
                continue

            if data:
                src = addr[0]
                if is_allowed(src, nets):
                    recv_time = datetime.now().astimezone().isoformat(timespec="milliseconds")
                    for msg in split_records(data.decode("utf-8", "replace")):
                        body = "%s\t%s\t%s" % (recv_time, src, msg)
                        line = body + "\n"
                        log.write(line)
                        log.flush()
                        if args.verbose:
                            sys.stdout.write(line)
                            sys.stdout.flush()
                        pending += len(line)
                        if cond is not None:
                            try:
                                cond.add(recv_time, src, msg)
                                cond.note_raw(body)
                            except Exception:
                                pass  # condensation must never affect ingestion
                elif args.verbose:
                    print("dropped datagram from %s" % src, file=sys.stderr)

            if pending and (pending >= SIZE_CHECK_BYTES or data is None):
                pending = 0
                log = enforce_cap(log, args.log_file, cap_bytes, args.keep_pct)
            if cond is not None and time.time() - cond.last_flush >= args.condense_every:
                try:
                    cond.flush()
                except Exception:
                    pass  # condense file locked/unwritable: retry next interval
    finally:
        if cond is not None:
            try:
                cond.flush()
            except Exception:
                pass
        log.close()
        sock.close()


def main(argv=None):
    args = parse_args(argv)
    while True:  # supervisor: never exit, Task Scheduler restart is the backstop
        try:
            serve(args)
        except KeyboardInterrupt:
            return 0
        except Exception:
            if args.verbose:
                import traceback
                traceback.print_exc()
            time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
