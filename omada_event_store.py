"""Durable, local per-record history for the Omada receiver."""

import base64
import hashlib
import ipaddress
import json
import os
import re
import shutil
import sqlite3
import tempfile
import uuid
from collections import deque
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

EXTRACTION_VERSION = 1
DEFAULT_MAX_MB = 500
BACKFILL_BATCH = 256
JOURNAL_MAX_BYTES = 64 << 20
JOURNAL_MIN_ENTRY_BYTES = 4096
UNKNOWN_TIME = -(1 << 62)
EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
MAC_RE = re.compile(r"(?:[0-9a-f]{12}|[0-9a-f]{2}(?P<sep>[:-])(?:[0-9a-f]{2}(?P=sep)){4}[0-9a-f]{2})", re.I)
CURSOR_RE = re.compile(r"([0-9a-f]{32}):([0-9]{1,19}):(-?[0-9]{1,19}):([0-9]{1,19})")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT,
    received_us INTEGER NOT NULL,
    source TEXT,
    raw BLOB NOT NULL,
    activity TEXT NOT NULL,
    ip TEXT,
    mac TEXT,
    origin TEXT NOT NULL,
    legacy_offset INTEGER UNIQUE,
    event_key TEXT UNIQUE,
    extraction_version INTEGER NOT NULL,
    metadata TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events(received_us, id);
CREATE INDEX IF NOT EXISTS events_ip ON events(ip, received_us, id) WHERE ip IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_mac ON events(mac, received_us, id) WHERE mac IS NOT NULL;
CREATE INDEX IF NOT EXISTS events_source ON events(source, received_us, id);
CREATE INDEX IF NOT EXISTS events_activity ON events(activity, received_us, id);
CREATE TABLE IF NOT EXISTS coverage (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    instance_id TEXT NOT NULL,
    cutover_at TEXT NOT NULL,
    raw_path TEXT NOT NULL,
    legacy_total_bytes INTEGER NOT NULL,
    legacy_imported_bytes INTEGER NOT NULL DEFAULT 0,
    evicted_count INTEGER NOT NULL DEFAULT 0,
    retention_target_bytes INTEGER NOT NULL
);
"""

INSERT = """
INSERT INTO events (received_at, received_us, source, raw, activity, ip, mac,
                    origin, legacy_offset, event_key, extraction_version, metadata)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def default_event_path(raw_path):
    raw_path = Path(raw_path)
    name = ("events.sqlite3" if raw_path.name.lower() == "firewall.log"
            else raw_path.stem + ".events.sqlite3")
    return str(raw_path.with_name(name))


def _now():
    return datetime.now().astimezone().isoformat(timespec="milliseconds")


def _time_us(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.utcoffset() is None:
        raise ValueError("timestamps require a UTC offset")
    delta = dt - EPOCH
    return (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds


def _mac(value):
    if not MAC_RE.fullmatch(value):
        raise ValueError("invalid MAC address")
    digits = value.lower().replace(":", "").replace("-", "")
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _enrich(received_at, source, raw, origin, legacy_offset=None, event_key=None):
    # Imported lazily so the viewer can also import the store for read access.
    from omada_viz import parse_raw_line

    activity = "malformed"
    ip = mac = None
    metadata = {}
    received_us = UNKNOWN_TIME
    try:
        if received_at is not None:
            received_us = _time_us(received_at)
        if received_at is not None and source is not None and raw:
            ipaddress.ip_address(source)
            decoded = raw.decode("utf-8").replace("\x00", "")
            parsed = parse_raw_line(f"{received_at}\t{source}\t{decoded}")
            if parsed:
                activity = ("flow" if parsed["type"] == "flow"
                            else parsed["activity"]["id"])
                fields = parsed.get("activity", {}).get("variables", {})
                if "ip" in fields:
                    ip = str(ipaddress.ip_address(fields["ip"]))
                if "client_mac" in fields:
                    mac = _mac(fields["client_mac"])
                metadata = {key: value for key, value in parsed.items()
                            if key not in ("ts", "sender", "message", "label")}
    except (ValueError, OverflowError):
        activity = "malformed"
        ip = mac = None
    if received_us == UNKNOWN_TIME:
        received_at = None
    return (received_at, received_us, source, raw, activity, ip, mac,
            origin, legacy_offset, event_key, EXTRACTION_VERSION,
            json.dumps(metadata, ensure_ascii=False, separators=(",", ":")))


def _legacy_record(line, offset):
    if line.endswith(b"\n"):
        line = line[:-1]
        if line.endswith(b"\r"):
            line = line[:-1]
    parts = line.split(b"\t", 2)
    if len(parts) == 3:
        try:
            timestamp, source = (part.decode("ascii") for part in parts[:2])
            _time_us(timestamp)
            ipaddress.ip_address(source)
            return _enrich(timestamp, source, parts[2], "legacy", offset)
        except (ValueError, OverflowError):
            pass
    return _enrich(None, None, line, "legacy", offset)


def _atomic_write(path, write):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}-")
    try:
        with os.fdopen(fd, "wb") as stream:
            write(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _error_path(path):
    return Path(str(path) + ".errors.json")


def _read_errors(path):
    try:
        with _error_path(path).open(encoding="utf-8") as stream:
            status = json.load(stream)
            if (not isinstance(status, dict) or not isinstance(status.get("live_missed_count"), int)
                    or not isinstance(status.get("write_error"), str)):
                raise ValueError("invalid event history diagnostic")
            return status
    except FileNotFoundError:
        return {"live_missed_count": 0, "write_error": None, "last_error_at": None}


def record_error(path, reason, missed=0):
    """Keep a durable history gap even if the database itself is unavailable."""
    status = _read_errors(path)
    status.update(write_error=reason, last_error_at=_now(),
                  live_missed_count=status["live_missed_count"] + missed)
    _atomic_write(_error_path(path), lambda stream: stream.write(
        json.dumps(status, separators=(",", ":")).encode("utf-8")))


def clear_recovered_error(path, *reasons):
    status = _read_errors(path)
    if not status["live_missed_count"] and status["write_error"] in reasons:
        _error_path(path).unlink(missing_ok=True)


def _writer_lock(path):
    """Hold an OS lock for the receiver's lifetime, including across cutover."""
    stream = open(str(path) + ".writer.lock", "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        stream.close()
        raise StoreConflict("event history already has a writer") from error
    return stream


class StoreConflict(ValueError):
    """This configuration would share the store with another receiver."""


def _journal_path(path):
    return Path(str(path) + ".pending")


def validate_store_paths(path, *protected_paths):
    """Reserve store files, directories and temporary names before any writes."""
    db = Path(path).resolve()
    pending = _journal_path(db)
    fixed = {db, *(Path(str(db) + suffix) for suffix in (
        ".legacy", ".legacy.seal", ".legacy.intent", ".errors.json", ".writer.lock",
        "-wal", "-shm", "-journal", ".pending",
    ))}
    aliases = fixed | {reserved.resolve() for reserved in fixed}
    prefixes = tuple(os.path.normcase(name) for name in (
        db.name + ".legacy-",
        "." + db.name + ".legacy-",
        "." + db.name + ".legacy.seal-",
        "." + db.name + ".legacy.intent-",
        "." + db.name + ".errors.json-",
    ))
    for value in protected_paths:
        if value is None:
            continue
        other = Path(value).resolve()
        linked = other.is_file() and any(
            reserved.is_file() and other.samefile(reserved) for reserved in fixed
        )
        if (other in aliases or linked or pending.resolve() in other.parents or
                (other.parent == db.parent and os.path.normcase(other.name).startswith(prefixes))):
            raise StoreConflict("event history files must be separate from the raw log and tallies")


def _pending_entries(path):
    try:
        entries = [entry for entry in _journal_path(path).iterdir()
                   if re.fullmatch(r"(?:[0-9a-f]{32}|q[0-9]{20}-[0-9a-f]{32})\.json",
                                   entry.name)]
    except FileNotFoundError:
        return []
    # Old journal entries used random UUID names, so their order cannot be
    # recovered after a restart. Keep those ahead of newly sequenced entries.
    return sorted(entries, key=lambda entry: (
        entry.name.startswith("q"),
        int(entry.name[1:21]) if entry.name.startswith("q") else 0,
        entry.name,
    ))


def _journal_batch_id(entry):
    match = re.fullmatch(r"q[0-9]{20}-([0-9a-f]{32})\.json", entry.name)
    return match.group(1) if match else entry.stem


class EventJournal:
    """Own the cutover boundary and hold durable batches awaiting SQLite."""

    def __init__(self, path, raw_path):
        self.path = Path(path).resolve()
        self.raw_path = Path(raw_path).resolve()
        self.seal = Path(str(self.path) + ".legacy.seal")
        self.intent = Path(str(self.path) + ".legacy.intent")
        self.pending = _journal_path(self.path)
        validate_store_paths(self.path, self.raw_path)
        if self.seal.is_symlink() or self.intent.is_symlink() or self.pending.is_symlink():
            raise OSError("event cutover sidecars cannot be symbolic links")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = _writer_lock(self.path)
        try:
            self.total = self._seal_snapshot()
            self.entries = deque(_pending_entries(self.path))
            self.pending_bytes = sum(self._cost(entry.stat().st_size) for entry in self.entries)
            self.next_sequence = max((
                int(entry.name[1:21]) + 1 for entry in self.entries
                if entry.name.startswith("q")
            ), default=0)
        except BaseException:
            self.close()
            raise

    def _owned_snapshot(self, record):
        if (not isinstance(record, dict) or not isinstance(record.get("snapshot_id"), str) or
                not re.fullmatch(r"[0-9a-f]{32}", record["snapshot_id"]) or
                not isinstance(record.get("raw_path"), str)):
            raise OSError("invalid event snapshot ownership record")
        if Path(record["raw_path"]) != self.raw_path:
            raise StoreConflict("event database belongs to a different raw log")
        snapshot = Path(str(self.path) + ".legacy-" + record["snapshot_id"])
        try:
            stat = snapshot.lstat()
        except FileNotFoundError:
            pass
        else:
            if snapshot.is_symlink() or [stat.st_dev, stat.st_ino] != record.get("identity"):
                raise OSError("sealed event snapshot was replaced")
        return snapshot

    @staticmethod
    def _read_record(path):
        with path.open(encoding="utf-8") as stream:
            return json.load(stream)

    @staticmethod
    def _write_record(path, record):
        _atomic_write(path, lambda stream: stream.write(
            json.dumps(record, separators=(",", ":")).encode("utf-8")))

    def _create_seal(self):
        snapshot_id = uuid.uuid4().hex
        snapshot = Path(str(self.path) + ".legacy-" + snapshot_id)
        record = None
        try:
            with snapshot.open("xb") as output:
                stat = os.fstat(output.fileno())
                record = {"raw_path": str(self.raw_path), "snapshot_id": snapshot_id,
                          "identity": [stat.st_dev, stat.st_ino]}
                # Record ownership before putting any legacy data in the copy.
                self._write_record(self.intent, record)
                try:
                    source = self.raw_path.open("rb")
                except FileNotFoundError:
                    pass
                else:
                    with source:
                        shutil.copyfileobj(source, output, length=1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
                size = output.tell()
            seal = {**record, "size": size}
            self._write_record(self.seal, seal)
        except BaseException:
            if record is not None and not self.seal.exists() and not self.pending.exists():
                self._owned_snapshot(record).unlink(missing_ok=True)
                self.intent.unlink(missing_ok=True)
            raise
        return seal

    def _seal_snapshot(self):
        try:
            seal = self._read_record(self.seal)
        except FileNotFoundError:
            # The writer lock is held, and no live journal can refer to this
            # snapshot until cutover is published.
            if self.pending.exists():
                raise OSError("event journal exists without a valid cutover seal")
            if self.path.exists() and self.path.stat().st_size:
                raise OSError("existing event database has no valid cutover seal")
            try:
                abandoned = self._read_record(self.intent)
            except FileNotFoundError:
                pass
            else:
                self._owned_snapshot(abandoned).unlink(missing_ok=True)
                self.intent.unlink()
            seal = self._create_seal()
        if not isinstance(seal, dict) or not isinstance(seal.get("size"), int) or seal["size"] < 0:
            raise OSError("invalid event cutover seal")
        self.snapshot = self._owned_snapshot(seal)
        try:
            intent = self._read_record(self.intent)
        except (OSError, ValueError):
            pass
        else:
            # A crash after publishing a seal can leave its intent behind.
            # Keep any other intent and any file it references untouched.
            if intent == {key: value for key, value in seal.items() if key != "size"}:
                self.intent.unlink(missing_ok=True)
        return seal["size"]

    @staticmethod
    def _cost(size):
        return max(size, JOURNAL_MIN_ENTRY_BYTES)

    @property
    def pending_replay(self):
        return bool(self.entries)

    def save(self, key, received_at, source, records):
        data = json.dumps([received_at, source,
                           [base64.b64encode(raw).decode("ascii") for raw in records]],
                          separators=(",", ":")).encode("ascii")
        cost = self._cost(len(data))
        if self.pending_bytes + cost > JOURNAL_MAX_BYTES:
            raise OSError("event recovery journal is full")
        self.pending.mkdir(exist_ok=True)
        for entry in self.entries:
            if _journal_batch_id(entry) == key:
                if entry.read_bytes() != data:
                    raise OSError("event recovery journal batch identity collision")
                return
        entry = self.pending / ("q%020d-%s.json" % (self.next_sequence, key))
        _atomic_write(entry, lambda stream: stream.write(data))
        self.pending_bytes += cost
        self.entries.append(entry)
        self.next_sequence += 1

    def replay(self, store, limit=16):
        for _ in range(min(limit, len(self.entries))):
            entry = self.entries[0]
            size = entry.stat().st_size
            with entry.open(encoding="ascii") as stream:
                received_at, source, records = json.load(stream)
            store.add(received_at, source, [base64.b64decode(raw, validate=True) for raw in records],
                      batch_id=_journal_batch_id(entry))
            entry.unlink()
            self.entries.popleft()
            self.pending_bytes -= self._cost(size)

    def commit_live(self, store, datagrams, replay_limit=16):
        """Commit a burst after older journal entries, or append it to the journal."""
        replay_error = None
        if self.pending_replay:
            try:
                self.replay(store, limit=replay_limit)
            except (OSError, sqlite3.Error, ValueError) as error:
                replay_error = error
        if self.pending_replay:
            for batch in datagrams:
                self.save(*batch)
        elif datagrams:
            store.add_batch(datagrams)
        return replay_error

    def close(self):
        self.lock.close()


class EventStore:
    """Single receiver writer. Readers use their own read-only connections."""

    def __init__(self, path, raw_path, max_bytes, journal=None):
        self.path = Path(path).resolve()
        self.raw_path = Path(raw_path).resolve()
        self.max_bytes = max_bytes
        self.owns_journal = journal is None
        self.journal = EventJournal(path, raw_path) if journal is None else journal
        self.snapshot = self.journal.snapshot
        self.connection = None
        try:
            self.connection = sqlite3.connect(self.path, timeout=0.25)
            mode = self.connection.execute("PRAGMA journal_mode=WAL").fetchone()[0]
            if mode.lower() != "wal":
                raise sqlite3.OperationalError("could not enable event database WAL")
            self.connection.execute("PRAGMA synchronous=FULL")
            self.connection.executescript(SCHEMA)
            self._prepare_backfill()
        except BaseException:
            self.close()
            raise

    def _prepare_backfill(self):
        db = self.connection
        row = db.execute("""
            SELECT raw_path, legacy_total_bytes, legacy_imported_bytes FROM coverage
        """).fetchone()
        if row is None:
            total = self.journal.total
            if not self.snapshot.exists() or self.snapshot.stat().st_size != total:
                raise OSError("sealed legacy snapshot unavailable while initializing event history")
            imported = 0
            with db:
                db.execute("""
                    INSERT INTO coverage (singleton, instance_id, cutover_at, raw_path,
                                          legacy_total_bytes, retention_target_bytes)
                    VALUES (1, ?, ?, ?, ?, ?)
                """, (uuid.uuid4().hex, _now(), str(self.raw_path), total, self.max_bytes))
        else:
            raw_path, total, imported = row
            if raw_path != str(self.raw_path):
                raise StoreConflict("event database belongs to a different raw log")
            if total != self.journal.total:
                raise OSError("event history cutover differs from the sealed legacy snapshot")
            with db:
                db.execute("UPDATE coverage SET retention_target_bytes = ?", (self.max_bytes,))
        self.legacy_total_bytes = total
        self.legacy_imported_bytes = imported
        if imported == total:
            self.snapshot.unlink(missing_ok=True)

    @property
    def backfill_pending(self):
        return self.legacy_imported_bytes < self.legacy_total_bytes

    def backfill_batch(self, limit=BACKFILL_BATCH):
        """Insert one small batch and advance its byte checkpoint atomically."""
        if not self.backfill_pending:
            return
        with self.snapshot.open("rb") as stream:
            if os.fstat(stream.fileno()).st_size != self.legacy_total_bytes:
                raise OSError("event history legacy snapshot size changed")
            offset = self.legacy_imported_bytes
            stream.seek(offset)
            batch = []
            for _ in range(limit):
                line = stream.readline()
                if not line:
                    break
                batch.append(_legacy_record(line, offset))
                offset = stream.tell()
        with self.connection:
            self.connection.executemany(INSERT, batch)
            self.connection.execute("UPDATE coverage SET legacy_imported_bytes = ?", (offset,))
        self.legacy_imported_bytes = offset
        if not self.backfill_pending:
            self.snapshot.unlink(missing_ok=True)

    def add(self, received_at, source, records, batch_id=None):
        self.add_batch([(batch_id or uuid.uuid4().hex, received_at, source, records)])

    def add_batch(self, datagrams):
        """Durably commit a burst while retaining each datagram's retry identity."""
        rows = [_enrich(received_at, source, raw, "live", event_key=f"{batch_id}:{index}")
                for batch_id, received_at, source, records in datagrams
                for index, raw in enumerate(records)]
        with self.connection:
            self.connection.executemany(INSERT + "ON CONFLICT(event_key) DO NOTHING", rows)

    def apply_retention(self):
        """Reclaim reusable SQLite pages by evicting the oldest rows first."""
        if self.journal.pending_replay:
            # Keep any ambiguously committed events until their retries resolve.
            return
        db = self.connection
        page_size = db.execute("PRAGMA page_size").fetchone()[0]

        def used_bytes():
            pages = db.execute("PRAGMA page_count").fetchone()[0]
            free = db.execute("PRAGMA freelist_count").fetchone()[0]
            return (pages - free) * page_size

        used = used_bytes()
        if used <= self.max_bytes:
            return
        target = self.max_bytes * 95 // 100
        remaining = db.execute("SELECT count(*) FROM events").fetchone()[0]
        # Bound maintenance time in the UDP loop. Freed pages can be reused.
        for _ in range(4):
            if remaining <= 1:
                break
            estimate = remaining * (used - target) // used
            count = min(max(1, estimate), 512, remaining - 1)
            with db:
                deleted = db.execute("""
                    DELETE FROM events WHERE id IN (
                        SELECT id FROM events ORDER BY received_us, id LIMIT ?
                    )
                """, (count,)).rowcount
                db.execute("UPDATE coverage SET evicted_count = evicted_count + ?", (deleted,))
            remaining -= deleted
            used = used_bytes()
            if deleted == 0 or used <= target:
                break

    def close(self):
        try:
            if self.connection is not None:
                self.connection.close()
        finally:
            if self.owns_journal:
                self.journal.close()


def _reader(path):
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True, timeout=0.5)


def event_status(path):
    errors = _read_errors(path)
    pending = len(_pending_entries(path))
    status = {"state": "unavailable", "legacy_state": "pending",
              "legacy_total_bytes": 0, "legacy_imported_bytes": 0, "evicted_count": 0,
              "cutover_at": None, "retention_target_bytes": None,
              "pending_live_batches": pending, **errors}
    if not Path(path).exists():
        return status
    with closing(_reader(path)) as db:
        db.row_factory = sqlite3.Row
        row = db.execute("""
            SELECT cutover_at, legacy_total_bytes, legacy_imported_bytes,
                   evicted_count, retention_target_bytes FROM coverage
        """).fetchone()
    if row is None:
        return status
    status.update(row)
    backfill = status["legacy_imported_bytes"] < status["legacy_total_bytes"]
    status["legacy_state"] = "pending" if backfill else "complete"
    status["state"] = ("degraded" if errors["write_error"] or pending else
                       "backfilling" if backfill else "ready")
    return status


def query_events(path, *, limit=100, cursor=None, ip=None, mac=None, activity=None,
                 text=None, since=None, until=None, source=None, sort="received_at_desc"):
    """Read bounded chronological pages. Continuations ignore newly inserted rows."""
    if not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ValueError("limit must be between 1 and 200")
    if sort not in ("received_at_asc", "received_at_desc"):
        raise ValueError("invalid event sort")
    order = "ASC" if sort == "received_at_asc" else "DESC"
    filters = []
    args = []

    def add(condition, value):
        filters.append(condition)
        args.append(value)

    if ip is not None:
        add("ip = ?", str(ipaddress.ip_address(ip)))
    if mac is not None:
        add("mac = ?", _mac(mac))
    if activity is not None:
        add("activity = ?", activity)
    if source is not None:
        add("source = ?", str(ipaddress.ip_address(source)))
    if text:
        add("instr(lower(CAST(raw AS TEXT)), lower(?)) > 0", text)
    if since is not None:
        add("received_us >= ?", _time_us(since))
    if until is not None:
        add("received_us <= ?", _time_us(until))
    query_identity = json.dumps([order, filters, args], separators=(",", ":"))
    if cursor is not None:
        match = CURSOR_RE.fullmatch(cursor)
        if not match:
            raise ValueError("invalid event cursor")
        cursor_identity, upper, timestamp, event_id = match.groups()
        upper, timestamp, event_id = map(int, (upper, timestamp, event_id))
        if not 1 <= event_id <= upper < (1 << 63) or not UNKNOWN_TIME <= timestamp < (1 << 63):
            raise ValueError("invalid event cursor")
        filters.append("(received_us, id) " + ("<" if order == "DESC" else ">") + " (?, ?)")
        args.extend((timestamp, event_id))
    if not Path(path).exists():
        return {"items": [], "next_cursor": None}
    with closing(_reader(path)) as db:
        db.row_factory = sqlite3.Row
        db.execute("BEGIN")
        coverage = db.execute("SELECT instance_id FROM coverage").fetchone()
        if coverage is None:
            return {"items": [], "next_cursor": None}
        identity = hashlib.sha256((coverage["instance_id"] + query_identity).encode()).hexdigest()[:32]
        if cursor is not None and cursor_identity != identity:
            raise ValueError("event cursor does not match store, filters or sort")
        if cursor is None:
            upper = db.execute("SELECT coalesce(max(id), 0) FROM events").fetchone()[0]
        add("id <= ?", upper)
        rows = db.execute("""
            SELECT id, received_at, received_us, source, raw, activity, ip, mac,
                   origin, extraction_version, metadata
            FROM events WHERE """ + " AND ".join(filters) + """
            ORDER BY received_us """ + order + ", id " + order + """ LIMIT ?
        """, (*args, limit + 1)).fetchall()
    items = []
    for row in rows[:limit]:
        item = dict(row)
        item.pop("received_us")
        raw = item["raw"]
        try:
            item["raw"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            item["raw"] = raw.decode("utf-8", "replace")
            item["raw_base64"] = base64.b64encode(raw).decode("ascii")
        item["metadata"] = json.loads(item["metadata"])
        item["parse_status"] = (item["activity"] if item["activity"] in ("unknown", "malformed")
                                else "parsed")
        items.append(item)
    next_cursor = None
    if len(rows) > limit:
        last = rows[limit - 1]
        next_cursor = f"{identity}:{upper}:{last['received_us']}:{last['id']}"
    return {"items": items, "next_cursor": next_cursor}
