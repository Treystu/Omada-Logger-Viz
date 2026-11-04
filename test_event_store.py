import base64
import contextlib
import io
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from omada_event_store import (
    EventJournal, EventStore, StoreConflict, clear_recovered_error,
    event_status, query_events, record_error,
)
from omada_syslog import enforce_cap, open_log, parse_args, split_records

FIRST = "2026-11-03T02:00:00.000-10:00"
SECOND = "2026-11-03T12:01:00.000+00:00"
SOURCE = "192.168.0.1"
DHCP = (b"<134>1 2026-11-03 02:00:00 ER8411 DHCP - - "
        b"DHCP Server allocated IP address 192.168.0.25 for the [client:AA-BB-CC-DD-EE-FF].")


def envelope(raw, timestamp=FIRST):
    return f"{timestamp}\t{SOURCE}\t".encode() + raw + b"\n"


class EventStoreTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.raw = Path(self.temp.name) / "firewall.log"
        self.path = self.raw.with_name("events.sqlite3")

    def open_store(self, size=500 << 20):
        return contextlib.closing(EventStore(self.path, self.raw, size))

    def test_snapshot_resume_preserves_duplicates_and_malformed_lines(self):
        contents = envelope(DHCP) * 2 + b"malformed\tlegacy\xff\n" + b"\n" + envelope(b"unknown")
        self.raw.write_bytes(contents)
        self.assertEqual(event_status(self.path)["state"], "unavailable")
        with self.open_store() as store:
            store.backfill_batch(limit=1)
            self.assertEqual(event_status(self.path)["state"], "backfilling")
            self.assertEqual(event_status(self.path)["legacy_imported_bytes"], len(envelope(DHCP)))
            store.add(SECOND, SOURCE, [DHCP])
            # The original may rotate while the receiver imports the sealed copy.
            self.raw.write_bytes(envelope(DHCP, SECOND))
        with self.open_store() as store:
            store.backfill_batch()
            self.assertFalse(store.backfill_pending)
            self.assertFalse(store.snapshot.exists())
        with self.open_store() as store:
            store.backfill_batch()
        self.assertEqual(event_status(self.path)["legacy_total_bytes"], len(contents))
        self.assertEqual(event_status(self.path)["state"], "ready")
        rows = query_events(self.path)["items"]
        self.assertEqual(len(rows), 6)
        self.assertEqual([row["origin"] for row in rows].count("live"), 1)
        associations = query_events(self.path, ip="192.168.0.25", mac="AABBCCDDEEFF")["items"]
        self.assertEqual(len(associations), 3)
        self.assertEqual({row["activity"] for row in associations}, {"dhcp_allocation"})
        self.assertEqual(len({row["id"] for row in associations}), 3)
        malformed = query_events(self.path, activity="malformed")["items"]
        self.assertEqual(len(malformed), 2)
        corrupted = next(row for row in malformed if row["raw"])
        self.assertEqual(base64.b64decode(corrupted["raw_base64"]), b"malformed\tlegacy\xff")

    def test_failed_backfill_transaction_retries_without_duplicate_rows(self):
        self.raw.write_bytes(envelope(DHCP) * 3)
        with self.open_store() as store:
            store.connection.executescript("""
                CREATE TRIGGER failed_checkpoint BEFORE UPDATE OF legacy_imported_bytes ON coverage
                BEGIN SELECT RAISE(ABORT, 'simulated checkpoint failure'); END;
            """)
            with self.assertRaises(sqlite3.IntegrityError):
                store.backfill_batch()
            self.assertEqual(query_events(self.path)["items"], [])
            self.assertEqual(event_status(self.path)["legacy_imported_bytes"], 0)
            store.connection.execute("DROP TRIGGER failed_checkpoint")
        with self.open_store() as store:
            store.backfill_batch()
            self.assertEqual(len(query_events(self.path)["items"]), 3)

    def test_sealed_copy_is_reused_when_cutover_commit_was_interrupted(self):
        self.raw.write_bytes(envelope(DHCP))
        with self.open_store() as store:
            # Simulate interruption after the atomic copy but before coverage was committed.
            with store.connection:
                store.connection.execute("DELETE FROM coverage")
            self.raw.write_bytes(envelope(b"later"))
        with self.open_store() as store:
            store.backfill_batch()
        self.assertEqual([row["raw"] for row in query_events(self.path)["items"]],
                         [DHCP.decode()])

    def test_keyset_pagination_ignores_interleaved_insertions_and_respects_order(self):
        with self.open_store() as store:
            store.add(FIRST, SOURCE, [b"literal % First", b"literal % second", b"other"])
            params = dict(text="LITERAL %", since="2026-11-03T12:00:00+00:00",
                          until=SECOND, source=SOURCE, limit=1)
            head = query_events(self.path, **params)
            store.add(FIRST, SOURCE, [b"literal % late"])
            tail = query_events(self.path, cursor=head["next_cursor"], **params)
            self.assertEqual([head["items"][0]["raw"], tail["items"][0]["raw"]],
                             ["literal % second", "literal % First"])
            self.assertIsNone(tail["next_cursor"])
            asc = query_events(self.path, sort="received_at_asc", **params)
            self.assertEqual(asc["items"][0]["raw"], "literal % First")
            with self.assertRaisesRegex(ValueError, "sort"):
                query_events(self.path, cursor=asc["next_cursor"], **params)
            with self.assertRaisesRegex(ValueError, "filters"):
                query_events(self.path, cursor=head["next_cursor"], text="other", limit=1)
            with self.assertRaises(ValueError):
                query_events(self.path, mac="AA-BB:CC-DD-EE-FF")

    def test_live_writes_are_independent_of_compatibility_log_rotation(self):
        payload = b"one\x00\r\n\x00\rtwo\xff"
        records = split_records(payload)
        self.assertEqual(records, [b"one\x00", b"two\xff"])
        with self.open_store() as store:
            store.add(FIRST, SOURCE, records)
            log = open_log(self.raw)
            log.write(envelope(DHCP).decode() * 3)
            log.flush()
            log = enforce_cap(log, self.raw, len(envelope(DHCP)) * 2, 90)
            log.close()
        with self.open_store() as store:
            self.assertFalse(store.backfill_pending)
            items = query_events(self.path)["items"]
            self.assertEqual([row["raw"] for row in items], ["two\ufffd", "one\x00"])
            self.assertEqual(base64.b64decode(items[0]["raw_base64"]), b"two\xff")

    def test_metadata_and_validation_distinguish_observed_messages(self):
        roam = (b"[client:AA:BB:CC:DD:EE:FF] is roaming from [ap:10:22:33:44:55:66][Channel 5] "
                b"to [ap:20:22:33:44:55:66][Channel 6] with SSID Office.")
        with self.open_store() as store:
            store.add(FIRST, SOURCE, [DHCP, roam, DHCP.replace(b"192.168.0.25", b"999.168.0.25"),
                                      b"<134>Sep 21 10:00:00 ER8411 DHCP: unclassified"])
        items = query_events(self.path)["items"]
        self.assertEqual([row["parse_status"] for row in items],
                         ["unknown", "malformed", "parsed", "parsed"])
        self.assertEqual(items[2]["activity"], "client_roaming")
        self.assertEqual(items[2]["metadata"]["activity"]["variables"]["ssid"], "Office")
        self.assertEqual(items[3]["metadata"]["tag"], "DHCP")
        self.assertIsNone(items[1]["ip"])

    def test_reader_contention_writer_conflict_and_persistent_error_status(self):
        with self.open_store() as store:
            with self.assertRaises(StoreConflict):
                self.open_store()
            with store.connection:
                store.connection.execute("UPDATE coverage SET legacy_imported_bytes = 42")
                self.assertEqual(event_status(self.path)["legacy_imported_bytes"], 0)
            record_error(self.path, "live_write_failed", 2)
        record_error(self.path, "store_unavailable", 1)
        self.assertEqual(event_status(self.path)["state"], "degraded")
        self.assertEqual(event_status(self.path)["live_missed_count"], 3)

    def test_database_lock_and_restart_recovers_identical_live_records(self):
        batch_id = uuid.uuid4().hex
        with self.open_store() as store, contextlib.closing(sqlite3.connect(self.path)) as blocker:
            blocker.execute("BEGIN IMMEDIATE")
            with self.assertRaises(sqlite3.OperationalError):
                store.add(FIRST, SOURCE, [DHCP, DHCP], batch_id=batch_id)
            store.journal.save(batch_id, FIRST, SOURCE, [DHCP, DHCP])
            record_error(self.path, "live_write_failed")
            self.assertEqual(event_status(self.path)["pending_live_batches"], 1)
            self.assertEqual(event_status(self.path)["state"], "degraded")
            blocker.rollback()
        with self.open_store() as store:
            store.journal.replay(store)
            clear_recovered_error(self.path, "live_write_failed")
        rows = query_events(self.path, activity="dhcp_allocation")["items"]
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0]["id"], rows[1]["id"])
        self.assertEqual(event_status(self.path)["state"], "ready")

    def test_committed_but_not_removed_journal_batch_replays_idempotently(self):
        batch_id = uuid.uuid4().hex
        with self.open_store() as store:
            store.journal.save(batch_id, FIRST, SOURCE, [DHCP, DHCP])
            store.add(FIRST, SOURCE, [DHCP, DHCP], batch_id=batch_id)
            # The process can stop after the commit but before unlinking the batch.
        with self.open_store() as store:
            store.journal.replay(store)
            store.add(FIRST, SOURCE, [DHCP])
            self.assertFalse(store.journal.pending_replay)
        self.assertEqual(len(query_events(self.path)["items"]), 3)

    def test_same_timestamp_live_batch_waits_behind_journal_across_outage_restart(self):
        older_id = "f" * 32
        newer_id = "0" * 32
        older_raw = b"same timestamp duplicate"
        newer_raw = b"same timestamp newer"
        with self.open_store() as store, contextlib.closing(sqlite3.connect(self.path)) as blocker:
            store.journal.save(older_id, FIRST, SOURCE, [older_raw, older_raw])
            blocker.execute("BEGIN IMMEDIATE")
            replay_error = store.journal.commit_live(
                store, [(newer_id, FIRST, SOURCE, [newer_raw, newer_raw])])
            self.assertIsInstance(replay_error, sqlite3.OperationalError)
            self.assertEqual(len(store.journal.entries), 2)
            blocker.rollback()

        # Reopening the journal must retain the append order even though the
        # batch identifiers sort in the opposite order and timestamps tie.
        with self.open_store() as store:
            store.journal.replay(store)
        rows = query_events(self.path, sort="received_at_asc")["items"]
        self.assertEqual([row["raw"].encode() for row in rows],
                         [older_raw, older_raw, newer_raw, newer_raw])
        self.assertEqual(len({row["id"] for row in rows}), 4)

    def test_burst_transaction_failure_rolls_back_all_datagrams(self):
        burst = [(uuid.uuid4().hex, FIRST, SOURCE, [DHCP, DHCP]),
                 (uuid.uuid4().hex, SECOND, SOURCE, [b"blocked"])]
        with self.open_store() as store:
            store.connection.executescript("""
                CREATE TRIGGER failed_datagram BEFORE INSERT ON events
                WHEN new.received_at = '2026-11-03T12:01:00.000+00:00'
                BEGIN SELECT RAISE(ABORT, 'simulated datagram failure'); END;
            """)
            with self.assertRaises(sqlite3.IntegrityError):
                store.add_batch(burst)
            self.assertEqual(query_events(self.path)["items"], [])
            for batch in burst:
                store.journal.save(*batch)
            store.connection.execute("DROP TRIGGER failed_datagram")
            store.journal.replay(store)
        self.assertEqual(len(query_events(self.path)["items"]), 3)

    def test_cutover_seal_survives_unavailable_database_during_initial_start(self):
        self.raw.write_bytes(envelope(DHCP))
        with contextlib.closing(EventJournal(self.path, self.raw)) as journal:
            # Startup established the boundary, but SQLite could not be opened.
            journal.save(uuid.uuid4().hex, SECOND, SOURCE, [DHCP])
            with self.raw.open("ab") as log:
                log.write(envelope(DHCP, SECOND))
        with self.open_store() as store:
            store.backfill_batch()
            store.journal.replay(store)
        rows = query_events(self.path)["items"]
        self.assertEqual([(row["origin"], row["received_at"]) for row in rows],
                         [("live", SECOND), ("legacy", FIRST)])

    def test_failed_seal_removes_owned_copy_on_every_retry(self):
        self.raw.write_bytes(envelope(DHCP))
        foreign = Path(str(self.path) + ".legacy-" + uuid.uuid4().hex)
        foreign.write_bytes(b"user file")
        write_record = EventJournal._write_record

        def fail_seal(path, record):
            if path.name.endswith(".seal"):
                raise OSError("simulated seal failure")
            write_record(path, record)

        with patch.object(EventJournal, "_write_record", side_effect=fail_seal):
            for _ in range(2):
                with self.assertRaisesRegex(OSError, "simulated"):
                    self.open_store()
                self.assertEqual(list(self.raw.parent.glob("events.sqlite3.legacy-*")), [foreign])
                self.assertFalse(Path(str(self.path) + ".legacy.intent").exists())
        with self.open_store() as store:
            store.backfill_batch()
        self.assertEqual(foreign.read_bytes(), b"user file")
        self.assertEqual(len(query_events(self.path)["items"]), 1)

    def test_restart_reclaims_only_snapshot_proven_by_abandoned_intent(self):
        snapshot_id = uuid.uuid4().hex
        abandoned = Path(str(self.path) + ".legacy-" + snapshot_id)
        abandoned.write_bytes(b"interrupted snapshot")
        info = abandoned.stat()
        intent = Path(str(self.path) + ".legacy.intent")
        EventJournal._write_record(intent, {
            "raw_path": str(self.raw.resolve()), "snapshot_id": snapshot_id,
            "identity": [info.st_dev, info.st_ino],
        })
        self.raw.write_bytes(envelope(DHCP))
        with self.open_store() as store:
            self.assertFalse(abandoned.exists())
            self.assertNotEqual(store.snapshot, abandoned)
            store.backfill_batch()
        self.assertEqual(len(query_events(self.path)["items"]), 1)

    def test_retry_preserves_snapshot_if_seal_was_published_before_error(self):
        self.raw.write_bytes(envelope(DHCP))
        write_record = EventJournal._write_record

        def publish_then_fail(path, record):
            write_record(path, record)
            if path.name.endswith(".seal"):
                raise OSError("simulated error after publication")

        with patch.object(EventJournal, "_write_record", side_effect=publish_then_fail):
            with self.assertRaisesRegex(OSError, "publication"):
                self.open_store()
        with self.raw.open("ab") as log:
            log.write(envelope(DHCP, SECOND))
        with self.open_store() as store:
            store.backfill_batch()
        rows = query_events(self.path)["items"]
        self.assertEqual([row["received_at"] for row in rows], [FIRST])

    def test_reserved_paths_are_rejected_before_touching_user_files(self):
        original = b"user data"
        for suffix in (".legacy", ".legacy.seal", "-wal", "-shm", ".writer.lock",
                       ".errors.json", ".pending/receiver.log", ".legacy-unused"):
            with self.subTest(suffix=suffix):
                protected = Path(str(self.path) + suffix)
                protected.parent.mkdir(exist_ok=True)
                protected.write_bytes(original)
                with self.assertRaises(StoreConflict):
                    self.open_store_with_raw(protected)
                with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    parse_args(["--event-file", str(self.path), "--condense-file", str(protected)])
                self.assertEqual(protected.read_bytes(), original)
        self.assertFalse(self.path.exists())

    def open_store_with_raw(self, raw_path):
        return contextlib.closing(EventStore(self.path, raw_path, 500 << 20))

    def test_udp_receiver_replays_outage_batches_after_restart(self):
        def wait_for(check):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if check():
                    return
                time.sleep(0.05)
            self.fail("timed out waiting for receiver")

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]

        @contextlib.contextmanager
        def running_receiver():
            proc = subprocess.Popen(
                [sys.executable, str(Path(__file__).with_name("omada_syslog.py")),
                 "--bind", "127.0.0.1", "--allow", "127.0.0.1", "--port", str(port),
                 "--log-file", str(self.raw), "--no-condense"],
                env={**os.environ, "LOCALAPPDATA": self.temp.name},
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                yield
            finally:
                proc.terminate()
                proc.wait(timeout=5)

        def ready():
            heartbeat = Path(self.temp.name) / "OmadaSyslog" / "receiver.heartbeat"
            return heartbeat.is_file() and event_status(self.path)["state"] == "ready"

        with contextlib.closing(sqlite3.connect(self.path)) as blocker, running_receiver():
            wait_for(ready)
            blocker.execute("BEGIN IMMEDIATE")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.sendto(DHCP + b"\n" + DHCP, ("127.0.0.1", port))
            wait_for(lambda: event_status(self.path)["pending_live_batches"] == 1)
            wait_for(lambda: self.raw.read_bytes().count(DHCP) == 2)
            self.assertEqual(query_events(self.path)["items"], [])
        with running_receiver():
            wait_for(ready)
            self.assertEqual(len(query_events(self.path, activity="dhcp_allocation")["items"]), 2)

    def test_retention_counts_evicted_rows_and_keeps_recent_history(self):
        with self.open_store(size=1 << 20) as store:
            bulk = b"old message " + b"X" * (10 << 10)
            store.add(FIRST, SOURCE, [bulk] * 90)
            store.add(SECOND, SOURCE, [b"most recent"])
            store.apply_retention()
            status = event_status(self.path)
            self.assertGreater(status["evicted_count"], 0)
            self.assertEqual(status["retention_target_bytes"], 1 << 20)
            self.assertEqual(query_events(self.path)["items"][0]["raw"], "most recent")
            count = store.connection.execute("SELECT count(*) FROM events").fetchone()[0]
            self.assertEqual(count + status["evicted_count"], 91)


if __name__ == "__main__":
    unittest.main()
