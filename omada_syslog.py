#!/usr/bin/env python3
"""Omada syslog receiver - a minimal UDP syslog collector for TP-Link Omada remote logging.

Listens on UDP 514 (default), accepts datagrams from allow-listed addresses
(default: the 192.168.0.0/24 LAN), stamps each message with receive time and
source IP, and appends the raw payload to a single log file. When the file
exceeds the size cap (default 50 MB) the oldest whole lines are trimmed away,
so the file stays around the cap - newest events always kept, oldest rolled
off first.

The receiver also writes each accepted record to a searchable SQLite history
before updating the raw compatibility log. On first use it imports the retained
raw backlog, and its default 500 MiB retention target is separate from the raw
log cap.

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
import json
import math
import os
import re
import socket
import sqlite3
import sys
import tempfile
import time
import uuid
from datetime import datetime

from omada_event_store import (
    DEFAULT_MAX_MB as DEFAULT_EVENT_MAX_MB, EventJournal, EventStore, StoreConflict,
    clear_recovered_error, default_event_path, record_error, validate_store_paths,
)

DEFAULT_BIND = "0.0.0.0"
DEFAULT_PORT = 514
DEFAULT_ALLOW = ["192.168.0.0/24"]
_LOCAL_APPDATA = (os.environ.get("LOCALAPPDATA")
                  or os.path.join(os.path.expanduser("~"), "AppData", "Local"))
DEFAULT_LOG_FILE = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "firewall.log")
DEFAULT_HEARTBEAT_FILE = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "receiver.heartbeat")
DEFAULT_RECOVERY_STATUS_FILE = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "recovery-status.json")
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
RAW_PENDING_IDLE_S = 0.25        # trim outstanding raw writes shortly after a burst
MAX_DATAGRAM_BATCH = 64          # drain only already-ready datagrams
HEARTBEAT_INTERVAL_S = 30.0      # refreshed even when no syslog traffic arrives
EVENT_BACKFILL_INTERVAL_S = 0.1
EVENT_RETRY_INTERVAL_S = 5.0


def refresh_heartbeat(path=DEFAULT_HEARTBEAT_FILE):
    """Touch a local liveness file; caller decides how to handle write errors."""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "a", encoding="ascii"):
        pass
    os.utime(path, None)


def refresh_heartbeat_if_due(path, last_update, now, interval=HEARTBEAT_INTERVAL_S):
    """Refresh a heartbeat after `interval`; return the new update time."""
    if now - last_update < interval:
        return last_update
    refresh_heartbeat(path)
    return now


def write_recovery_status(path, reason):
    """Atomically publish a safe, persistent recovery failure summary."""
    status = {
        "status": "recovery_failed",
        "updated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "reason": reason,
    }
    dirname = os.path.dirname(os.path.abspath(path))
    os.makedirs(dirname, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dirname, prefix=".recovery-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(status, f, separators=(",", ":"))
        os.replace(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def clear_recovery_status(path):
    """Clear a prior failure only after a successful recovery pass."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def recovery_failure_reason(error):
    message = str(error).lower()
    if "ambiguous" in message:
        return "legacy_marker_ambiguous"
    if "marker line no longer present" in message:
        return "checkpoint_missing"
    return "recovery_error"


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
    p.add_argument("--event-file",
                   help="SQLite event history (default: next to the raw log)")
    p.add_argument("--event-max-mb", type=float, default=DEFAULT_EVENT_MAX_MB,
                   help="SQLite retained data target in MiB, excluding reusable pages and WAL "
                        "(default: %(default)s)")
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
                   help="disable aggregate tallies")
    p.add_argument("--verbose", action="store_true",
                   help="echo received lines to stdout, dropped datagrams to stderr")
    args = p.parse_args(argv)
    if not 1 <= args.port <= 65535:
        p.error("port must be 1-65535")
    if args.max_mb <= 0:
        p.error("--max-mb must be positive")
    if not math.isfinite(args.event_max_mb) or args.event_max_mb < 1:
        p.error("--event-max-mb must be finite and at least 1")
    if args.event_file is None:
        args.event_file = default_event_path(args.log_file)
    try:
        validate_store_paths(args.event_file, args.log_file, args.condense_file)
    except StoreConflict as error:
        p.error(str(error))
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
    String callers get the original NUL-stripped behavior. Byte callers keep
    the full payload for the event store, skipping NUL-only padding."""
    if isinstance(msg, bytes):
        return [record for record in re.split(rb"[\r\n]+", msg)
                if record.strip(b"\x00")]
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


def receive_datagrams(sock, timeout):
    """Wait for one datagram, then drain a bounded burst without waiting."""
    data, addr = sock.recvfrom(65536)
    datagrams = [(datetime.now().astimezone().isoformat(timespec="milliseconds"), data, addr[0])]
    sock.setblocking(False)
    try:
        for _ in range(MAX_DATAGRAM_BATCH - 1):
            try:
                data, addr = sock.recvfrom(65536)
            except OSError:
                # Queue drained or a transient Winsock error. Keep already-read datagrams.
                break
            datagrams.append((datetime.now().astimezone().isoformat(timespec="milliseconds"),
                              data, addr[0]))
    finally:
        sock.settimeout(timeout)
    return datagrams


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

    history = journal = None
    event_cap = int(args.event_max_mb * 1024 * 1024)
    next_event_error_log = 0

    def history_error(reason, error, missed=0):
        nonlocal next_event_error_log
        try:
            record_error(args.event_file, reason, missed)
        except (OSError, ValueError, TypeError) as diagnostic:
            print("could not write event history diagnostic: %s" % diagnostic,
                  file=sys.stderr, flush=True)
        now = time.monotonic()
        if now >= next_event_error_log:
            print("event history %s: %s" % (reason, error), file=sys.stderr, flush=True)
            next_event_error_log = now + EVENT_RETRY_INTERVAL_S

    def history_recovered(*reasons):
        try:
            clear_recovered_error(args.event_file, *reasons)
        except (OSError, ValueError) as error:
            history_error("diagnostic_unavailable", error)

    def open_history():
        nonlocal journal
        try:
            if journal is None:
                journal = EventJournal(args.event_file, args.log_file)
            store = EventStore(args.event_file, args.log_file, event_cap, journal=journal)
        except (OSError, sqlite3.Error, ValueError) as error:
            if isinstance(error, StoreConflict):
                raise
            history_error("startup_failed", error)
            return None
        if not journal.pending_replay:
            history_recovered("startup_failed", "live_write_failed", "live_replay_failed")
        return store

    try:
        # Seal the retained pre-cutover log before the first new raw append.
        history = open_history()
        log = open_log(args.log_file)
    except BaseException:
        if history is not None:
            history.close()
        if journal is not None:
            journal.close()
        sock.close()
        raise
    last_heartbeat = time.monotonic() - HEARTBEAT_INTERVAL_S

    def refresh_liveness():
        nonlocal last_heartbeat
        now = time.monotonic()
        if now - last_heartbeat < HEARTBEAT_INTERVAL_S:
            return
        try:
            refresh_heartbeat()
        except OSError:
            if args.verbose:
                print("could not update receiver heartbeat", file=sys.stderr)
        last_heartbeat = now

    # The socket is bound and the raw log is writable. Publish health before
    # potentially long condenser recovery, which calls refresh_liveness too.
    refresh_liveness()
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
            folded = cond.catch_up(args.log_file, progress=refresh_liveness)
        except Exception as e:
            # Without a valid recovery checkpoint, persisting live tallies
            # would move the marker past records that were never recovered.
            try:
                write_recovery_status(DEFAULT_RECOVERY_STATUS_FILE,
                                      recovery_failure_reason(e))
            except OSError as status_error:
                print("could not write recovery diagnostic: %s" % status_error,
                      file=sys.stderr, flush=True)
            print("condenser recovery failed; condensation disabled for this run: %s"
                  % e, file=sys.stderr, flush=True)
            cond = None
        else:
            try:
                clear_recovery_status(DEFAULT_RECOVERY_STATUS_FILE)
            except OSError as status_error:
                print("could not clear recovery diagnostic: %s" % status_error,
                      file=sys.stderr, flush=True)
        if cond is not None:
            try:
                cond.flush()
            except Exception:
                pass
            if args.verbose:
                print("condenser resumed: %d keys / %d records (catch-up folded %s lines)"
                      % (len(cond.state), cond.total, folded), file=sys.stderr)
    pending = 0
    next_history_open = time.monotonic() + EVENT_RETRY_INTERVAL_S
    next_backfill = next_retention = next_replay = 0
    receive_timeout = None
    try:
        while True:
            recovering = (history is not None
                          and (history.backfill_pending or journal.pending_replay))
            timeout = EVENT_BACKFILL_INTERVAL_S if recovering else SIZE_CHECK_IDLE_S
            if pending:
                timeout = min(timeout, RAW_PENDING_IDLE_S)
            if timeout != receive_timeout:
                sock.settimeout(timeout)
                receive_timeout = timeout
            datagrams = []
            try:
                datagrams = receive_datagrams(sock, timeout)
            except socket.timeout:
                pass
            except OSError:
                time.sleep(0.05)  # transient Winsock error (e.g. WSAECONNRESET)
                continue

            now = time.monotonic()
            if now - last_heartbeat >= HEARTBEAT_INTERVAL_S:
                refresh_liveness()

            if history is None and now >= next_history_open:
                history = open_history()
                next_history_open = now + EVENT_RETRY_INTERVAL_S
            accepted = []
            for recv_time, data, src in datagrams:
                if not data:
                    continue
                if is_allowed(src, nets):
                    records = split_records(data)
                    if records:
                        accepted.append((uuid.uuid4().hex, recv_time, src, records))
                elif args.verbose:
                    print("dropped datagram from %s" % src, file=sys.stderr)

            write_error = None
            replay_error = None
            if accepted and history is not None:
                try:
                    replay_error = journal.commit_live(history, accepted)
                except (OSError, sqlite3.Error) as error:
                    write_error = error
                    history.close()
                    history = None
                    next_history_open = now + EVENT_RETRY_INTERVAL_S
            if replay_error is not None:
                history_error("live_replay_failed", replay_error)
                next_replay = now + EVENT_BACKFILL_INTERVAL_S
            recovery_failed = False
            for batch_id, recv_time, src, records in accepted:
                if history is None:
                    try:
                        if journal is None:
                            raise OSError("event cutover seal unavailable")
                        journal.save(batch_id, recv_time, src, records)
                    except (OSError, ValueError) as error:
                        recovery_failed = True
                        history_error("live_recovery_failed", error, len(records))
                for record in records:
                    msg = record.replace(b"\x00", b"").decode("utf-8", "replace")
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
                            cond.note_raw(body, log.tell())
                        except Exception:
                            pass  # condensation must never affect ingestion
            if write_error is not None and not recovery_failed:
                history_error("live_write_failed", write_error)

            if history is not None:
                if journal.pending_replay and now >= next_replay:
                    try:
                        journal.replay(history)
                    except (OSError, sqlite3.Error, ValueError) as error:
                        history_error("live_replay_failed", error)
                        next_replay = now + EVENT_RETRY_INTERVAL_S
                    else:
                        next_replay = now + EVENT_BACKFILL_INTERVAL_S
                        if not journal.pending_replay:
                            history_recovered("startup_failed", "live_write_failed", "live_replay_failed")
                if history.backfill_pending and now >= next_backfill:
                    try:
                        history.backfill_batch()
                    except (OSError, sqlite3.Error) as error:
                        history_error("backfill_failed", error)
                        next_backfill = now + EVENT_RETRY_INTERVAL_S
                    else:
                        next_backfill = now + EVENT_BACKFILL_INTERVAL_S
                        if not history.backfill_pending:
                            history_recovered("backfill_failed")
                if now >= next_retention:
                    try:
                        history.apply_retention()
                    except (OSError, sqlite3.Error) as error:
                        history_error("retention_failed", error)
                    next_retention = now + SIZE_CHECK_IDLE_S

            if pending and (pending >= SIZE_CHECK_BYTES or not datagrams):
                pending = 0
                log = enforce_cap(log, args.log_file, cap_bytes, args.keep_pct)
            if cond is not None and time.time() - cond.last_flush >= args.condense_every:
                try:
                    cond.flush()
                except Exception:
                    pass  # condense file locked/unwritable: retry next interval
    finally:
        if history is not None:
            history.close()
        if journal is not None:
            journal.close()
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
        except StoreConflict as error:
            print(str(error), file=sys.stderr, flush=True)
            time.sleep(1)
        except Exception:
            if args.verbose:
                import traceback
                traceback.print_exc()
            time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
