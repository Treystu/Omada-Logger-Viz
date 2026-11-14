"""Versioned chart projections over the collector's two read-only files."""

import hashlib
import json
import math
import os
import secrets
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from threading import Lock


SCHEMA = 1
MAX_SOURCE_BYTES = 128 << 20
MAX_RAW_LINE_BYTES = 128 << 10
RAW_ANCHOR_BYTES = 64 << 10
RAW_SCAN_CHUNK = 1 << 20
MAX_ROWS = 150_000
MAX_DELTA_ROWS = 4096
MAX_DELTA_BYTES = 2 << 20
MAX_HISTORY_BYTES = 12 << 20
MAX_HISTORY = 32
MAX_DETAIL_REFS = 100
MAX_DETAIL_BYTES = 2 << 20
LAYERS = ("entries", "raw")
REMOTE_MESSAGE_LABEL = "(message text hidden for remote clients)"


def wire_json(value):
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode("ascii")


def _invalid_constant(value):
    raise ValueError("Invalid JSON constant: " + value)


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Invalid JSON number")
    return number


class ChartError(Exception):
    def __init__(self, status, message, **details):
        super().__init__(message)
        self.status = status
        self.details = details


def _legacy_fallback(message):
    return ChartError(501, message, fallback=True)


@dataclass
class Row:
    chart: dict
    source: object


@dataclass
class RawLine:
    data: bytes
    rows: tuple


@dataclass(frozen=True)
class RawSource:
    signature: tuple
    lines: dict
    anchor: tuple
    next_order: int


def _identity(stat):
    return stat.st_dev, stat.st_ino


def _signature(stat):
    return _identity(stat), stat.st_size, stat.st_mtime_ns, stat.st_ctime_ns


def _end_anchor(f, end):
    size = min(RAW_ANCHOR_BYTES, end)
    f.seek(end - size)
    data = f.read(size)
    if len(data) != size:
        raise OSError("raw log changed while reading")
    return hashlib.sha256(data).digest(), data.endswith(b"\n")


def _tail(f, end, limit):
    """Read a fixed prefix backwards and give each line its physical offset."""
    chunks = []
    newlines = 0
    pos = end
    while pos and newlines <= limit:
        size = min(RAW_SCAN_CHUNK, pos, MAX_SOURCE_BYTES - (end - pos))
        if not size:
            raise _legacy_fallback("Raw tail exceeds the compact chart byte limit.")
        pos -= size
        f.seek(pos)
        chunk = f.read(size)
        if len(chunk) != size:
            raise OSError("raw log changed while reading")
        chunks.append(chunk)
        newlines += chunk.count(b"\n")
    if not chunks:
        return {}
    buf = b"".join(reversed(chunks))
    if pos:
        start = buf.index(b"\n") + 1
        pos += start
        buf = buf[start:]
    lines = buf.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    else:
        # Treat an unterminated line as present, but changing it later breaks
        # raw continuity and will retire the old row reference.
        lines[-1] += b"\n"
    skip = max(0, len(lines) - limit)
    pos += sum(len(line) + 1 for line in lines[:skip])
    result = {}
    for line in lines[skip:]:
        result[pos] = line
        pos += len(line) + 1
    return result


def _remote_raw(row):
    if row["type"] != "msg":
        return row
    return {**{key: value for key, value in row.items() if key != "pattern_id"},
            "label": REMOTE_MESSAGE_LABEL}


class ChartCache:
    """Serialize refreshes and retain a bounded journal of immutable projections.

    Full source records live only in the current private in-process view. Old
    revisions retain compact chart rows, never a history of full records.
    """

    def __init__(self, args, project_tally, project_raw, detail_tally, detail_raw, recovery):
        self.args = args
        self.project_tally = project_tally
        self.project_raw = project_raw
        self.detail_record = {"entries": detail_tally, "raw": detail_raw}
        self.read_recovery = recovery
        self.epoch = secrets.token_urlsafe(18)
        self.pattern_key = secrets.token_bytes(32)
        self.revision = 0
        self.lock = Lock()
        self.layers = {layer: {} for layer in LAYERS}
        self.by_id = {}
        self.raw_state = None
        self.tally_signature = None
        self.status = {}
        self.history = deque()
        self.history_bytes = 0

    def _new_row(self, chart, source, order, old=None):
        return Row({**chart, "id": old.chart["id"] if old else secrets.token_urlsafe(12),
                    "order": order, "version": self.revision + 1}, source)

    def _condensed(self, old):
        try:
            with open(self.args.condense_file, "rb") as f:
                signature = _signature(os.fstat(f.fileno()))
                if self.tally_signature == signature:
                    return old, self.status["meta"], self.status["sources"]["condensed"], False, signature
                if signature[1] > MAX_SOURCE_BYTES:
                    raise _legacy_fallback("Condensed tallies exceed the compact chart byte limit.")
                state = json.loads(f.read(signature[1] + 1), parse_constant=_invalid_constant,
                                   parse_float=_finite_float)
                if signature != _signature(os.fstat(f.fileno())):
                    raise OSError("condensed source changed while reading")
            if not isinstance(state, dict):
                raise ValueError("condensed chart source must contain a JSON object")
            meta = state.pop("_meta", {})
            if len(state) > MAX_ROWS:
                raise _legacy_fallback("Condensed tallies exceed the compact chart row limit.")
            if not isinstance(meta, dict):
                meta = {}
            meta = {key: meta[key] for key, kind in (("records", int), ("keys", int), ("last_flush", str))
                    if type(meta.get(key)) is kind}
            total = len(state)
            state = {key: value for key, value in state.items() if self._tally_valid(value)}
            invalid = total - len(state)
            # The condenser appends keys. Keep order numbers across ordinary
            # evictions so the client need not replace every subsequent row.
            retained = [key for key in old if key in state]
            reorder = list(state)[:len(retained)] != retained
            previous_order = next(reversed(old.values())).chart["order"] if old else -1
            rows = {}
            for index, (key, value) in enumerate(state.items()):
                prior = old.get(key)
                if reorder:
                    order = index
                elif prior:
                    order = prior.chart["order"]
                else:
                    previous_order += 1
                    order = previous_order
                if prior and prior.source == value and prior.chart["order"] == order:
                    rows[key] = prior
                    continue
                if prior and (prior.source.get("first") != value.get("first") or
                              self._counter_decreased(prior.source, value)):
                    prior = None
                rows[key] = self._new_row(self.project_tally(value), value, order, prior)
            return (rows, meta, {"available": True, "entries": len(rows), "unparsed": invalid},
                    reorder, signature)
        except (OSError, ValueError, TypeError, RecursionError):
            return ({}, {}, {"available": False, "error": "Condensed tallies are unavailable or invalid."},
                    False, None)

    @staticmethod
    def _tally_valid(value):
        if not isinstance(value, dict) or value.get("type") not in (None, "flow", "msg"):
            return False
        text_keys = ("src", "dst", "ap", "from", "template", "first", "last")
        int_keys = ("proto", "dpt", "spt_sample", "sev", "count")
        occurrences = value.get("occurrences", [])
        return (all(value.get(key) is None or type(value[key]) is str for key in text_keys)
                and all(value.get(key) is None or type(value[key]) is int for key in int_keys)
                and isinstance(occurrences, list) and all(isinstance(ts, str) for ts in occurrences))

    @staticmethod
    def _counter_decreased(old, new):
        old_count, new_count = old.get("count"), new.get("count")
        return type(old_count) is int and type(new_count) is int and new_count < old_count

    def _raw_line(self, lines, order):
        rows = []
        for index, line in enumerate(lines):
            try:
                chart = self.project_raw(line)
            except (ValueError, TypeError):
                chart = None
            if chart is None:
                rows.append(None)
            else:
                if chart["type"] == "msg":
                    message = line.split("\t", 2)[2]
                    chart["pattern_id"] = hashlib.blake2s(message.encode("utf-8"),
                                                          key=self.pattern_key, digest_size=16).hexdigest()
                rows.append(self._new_row(chart, line, order + index))
        return tuple(rows)

    def _prepare_raw(self, lines, limit, previous_end):
        selected = []
        for offset, data in reversed(lines.items()):
            prior = None
            if previous_end is not None and offset < previous_end:
                prior = self.raw_state.lines.get(offset)
                if prior is None or prior.data != data:
                    return None
            if prior is not None:
                logical = prior.rows[-limit:]
            elif len(data) > MAX_RAW_LINE_BYTES:
                raise _legacy_fallback("A raw line exceeds the compact chart line limit.")
            else:
                # Match the legacy text splitter for Unicode separators.
                text = data[:-1] if data.endswith(b"\n") else data + b"\n"
                logical = text.decode("utf-8", "replace").splitlines()[-limit:]
            selected.append((offset, data, logical, prior is not None))
            limit -= len(logical)
            if limit <= 0:
                break
        return selected

    def _is_raw_append(self, f, previous, current):
        if (previous is None or not previous[0][1] or previous[0] != current[0]
                or previous[1] >= current[1]):
            return False
        end = previous[1]
        # Verify the previous end even after its last row falls out of the
        # visible tail. An unfinished line can change when writing resumes.
        if end == 0:
            return True
        return self.raw_state.anchor[1] and _end_anchor(f, end) == self.raw_state.anchor

    def _raw(self, old):
        previous = self.raw_state.signature if self.raw_state else None
        try:
            with open(self.args.log_file, "rb") as f:
                stat = os.fstat(f.fileno())
                signature = _signature(stat)
                if previous == signature:
                    return old, self.status["sources"]["raw"], False, self.raw_state
                requested = self.args.raw_tail
                if requested < 0 or (requested == 0 and stat.st_size > RAW_SCAN_CHUNK):
                    # The legacy zero setting exposes its last scan chunk,
                    # which can start partway through a physical line.
                    raise _legacy_fallback("This raw-tail configuration requires the legacy chart.")
                limit = min(requested or MAX_ROWS + 1, MAX_ROWS + 1)
                continued = self._is_raw_append(f, previous, signature)
                anchor = _end_anchor(f, stat.st_size)
                lines = _tail(f, stat.st_size, limit)
                if _end_anchor(f, stat.st_size) != anchor:
                    raise OSError("raw log changed while reading")
                now = os.stat(self.args.log_file)
                if (_identity(now) != _identity(stat) or now.st_size < stat.st_size
                        or (now.st_size == stat.st_size and now.st_mtime_ns != stat.st_mtime_ns)):
                    raise OSError("raw log changed while reading")
            if continued:
                selected = self._prepare_raw(lines, limit, previous[1])
                continued = selected is not None
            if not continued:
                selected = self._prepare_raw(lines, limit, None)
            if sum(len(logical) for _, _, logical, _ in selected) > MAX_ROWS:
                raise _legacy_fallback("Raw tail exceeds the compact chart row limit.")
            cached_lines = {}
            rows = {}
            unparsed = 0
            next_order = self.raw_state.next_order if continued else 0
            for offset, data, logical, reused in reversed(selected):
                if not reused:
                    logical = self._raw_line(logical, next_order)
                    next_order += len(logical)
                cached_lines[offset] = RawLine(data, logical)
                for row in logical:
                    if row is None:
                        unparsed += 1
                    else:
                        rows[row.chart["order"]] = row
            return (rows, {"available": True, "records": len(rows), "unparsed": unparsed},
                    bool(previous and not continued), RawSource(signature, cached_lines, anchor, next_order))
        except (OSError, ValueError, TypeError, RecursionError):
            return ({}, {"available": False, "error": "Raw log is unavailable or changed while reading."},
                    bool(previous), None)

    def _refresh(self):
        raw, raw_source, rotated, raw_state = self._raw(self.layers["raw"])
        entries, meta, condensed_source, reorder, tally_signature = self._condensed(self.layers["entries"])
        recovery = self.read_recovery()
        status = {"meta": meta, "sources": {"condensed": condensed_source, "raw": raw_source},
                  "recovery": recovery}
        updates = {key: value for key, value in status.items() if self.status.get(key) != value}
        layers = {"entries": entries, "raw": raw}
        # A capacity fallback from either source must leave the published
        # signatures, rows, and revision untouched.
        self.raw_state = raw_state
        self.tally_signature = tally_signature
        if not updates and all(rows is self.layers[layer] for layer, rows in layers.items()):
            return
        changes = []
        for layer, rows in layers.items():
            previous = self.layers[layer]
            if rows is previous:
                continue
            upserts = [row.chart for key, row in rows.items() if previous.get(key) is not row]
            deletes = [row.chart["id"] for key, row in previous.items()
                       if key not in rows or rows[key].chart["id"] != row.chart["id"]]
            for row_id in deletes:
                self.by_id.pop(row_id, None)
            for key, row in rows.items():
                if previous.get(key) is not row:
                    self.by_id[row.chart["id"]] = (layer, row)
            if upserts or deletes:
                changes.append({"layer": layer, "upserts": upserts, "deletes": deletes})
        self.layers = layers
        if not changes and not updates and not rotated:
            return
        self.revision += 1
        updates["generated"] = datetime.now().astimezone().isoformat(timespec="seconds")
        self.status.update(updates)
        count = sum(len(c["upserts"]) + len(c["deletes"]) for c in changes)
        if reorder or rotated or count > MAX_DELTA_ROWS:
            self.history.clear()
            self.history_bytes = 0
            return
        size = len(wire_json({"changes": changes, **updates}))
        if size > MAX_DELTA_BYTES:
            self.history.clear()
            self.history_bytes = 0
            return
        self.history.append((self.revision, changes, updates, size))
        self.history_bytes += size
        while len(self.history) > MAX_HISTORY or self.history_bytes > MAX_HISTORY_BYTES:
            self.history_bytes -= self.history.popleft()[3]

    def _header(self):
        return {"schema": SCHEMA, "epoch": self.epoch, "revision": self.revision}

    def _reset(self, message):
        return ChartError(409, message, reset=True)

    def snapshot(self, local):
        with self.lock:
            self._refresh()
            return {**self._header(), **self.status, "detail_available": local,
                    "redacted_detail_available": not local,
                    "entries": [row.chart for row in self.layers["entries"].values()],
                    "raw": [row.chart if local else _remote_raw(row.chart)
                            for row in self.layers["raw"].values()]}

    def changes(self, epoch, since, local):
        with self.lock:
            self._refresh()
            if epoch != self.epoch or since > self.revision:
                raise self._reset("Chart cursor is from a different view.")
            result = {**self._header(), "base": since, "changes": []}
            if since == self.revision:
                return result
            if not self.history or since < self.history[0][0] - 1:
                raise self._reset("Chart history expired. Refresh the snapshot.")
            edits = {layer: {} for layer in LAYERS}
            for revision, changes, updates, _ in self.history:
                if revision <= since:
                    continue
                result.update(updates)
                for change in changes:
                    layer = change["layer"]
                    for row_id in change["deletes"]:
                        edits[layer][row_id] = None
                    for row in change["upserts"]:
                        edits[layer][row["id"]] = row if local or layer == "entries" else _remote_raw(row)
            if sum(len(edit) for edit in edits.values()) > MAX_DELTA_ROWS:
                raise self._reset("Chart changes exceed the update limit.")
            for layer, edit in edits.items():
                if edit:
                    result["changes"].append({"layer": layer,
                                              "upserts": [row for row in edit.values() if row is not None],
                                              "deletes": [row_id for row_id, row in edit.items() if row is None]})
            if len(wire_json(result)) > MAX_DELTA_BYTES:
                raise self._reset("Chart changes exceed the byte limit.")
            return result

    def _record(self, row_id, version, local):
        item = self.by_id.get(row_id)
        if item is None:
            raise ChartError(404, "Chart record expired or is missing.")
        layer, row = item
        if row.chart["version"] != version:
            raise ChartError(409, "Chart record changed. Select it again after refreshing.")
        return self.detail_record[layer](row.source, local=local)

    def details(self, epoch, refs, single=False, local=True):
        with self.lock:
            if epoch != self.epoch:
                raise self._reset("Chart record belongs to a different view.")
            header = self._header()
            results = []
            size = 0
            for row_id, version in refs:
                result = {"id": row_id, "version": version}
                try:
                    result["record"] = self._record(row_id, version, local)
                    size += len(wire_json(result))
                    if size > MAX_DETAIL_BYTES:
                        raise ChartError(413, "Chart details exceed the response limit. Select fewer records.")
                except ChartError as e:
                    if single or e.status == 413:
                        raise
                    result.update(error=str(e), status=e.status)
                results.append(result)
            return {**header, **results[0]} if single else {**header, "results": results}

    def search(self, epoch, revision, query, local):
        with self.lock:
            if epoch != self.epoch or revision != self.revision:
                raise self._reset("Chart changed. Refresh before searching again.")
            header = self._header()
            layers = self.layers
        matches = {"pattern": [], "variables": [], "variable_values": [], "candidates": []}
        for layer, rows in layers.items():
            for row in rows.values():
                chart = row.chart
                if chart.get("type") != "msg":
                    continue
                row_id = chart["id"]
                activity = chart.get("activity", {})
                detail = self.detail_record[layer](row.source) if local else None
                if layer == "entries":
                    pattern = chart.get("template") or "(template unavailable)"
                else:
                    pattern = detail["message"] if local else REMOTE_MESSAGE_LABEL
                activity_id = activity.get("id")
                if not activity_id or activity_id == "unknown":
                    activity_id = "unknown:" + pattern
                pattern_parts = [pattern, activity.get("label", ""), activity_id]
                if not detail:
                    if query in " ".join(pattern_parts).lower():
                        matches["pattern"].append(row_id)
                    continue
                variables = detail.get("activity", {}).get("variables", {})
                values = [str(v) for val in variables.values()
                          for v in (val if isinstance(val, list) else [val])]
                if query in " ".join(pattern_parts).lower():
                    matches["pattern"].append(row_id)
                if query in " ".join([*pattern_parts, *variables, *values]).lower():
                    matches["variables"].append(row_id)
                if any(query in value.lower() for value in values):
                    matches["variable_values"].append(row_id)
                if any(query in str(candidate["value"]).lower() and str(candidate["value"]) not in values
                       for candidate in detail.get("candidates", [])):
                    matches["candidates"].append(row_id)
        return {**header, "matches": matches}
