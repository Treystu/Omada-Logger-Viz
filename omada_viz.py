#!/usr/bin/env python3
"""Omada syslog viz - local web UI: time-series scatterplot of the condensed
tallies plus the raw-log tail.

Read-only, localhost-only, zero dependencies (Python stdlib + vanilla JS/canvas).
Run on demand:

    python omada_viz.py                          # http://localhost:8780
    python omada_viz.py --port 9000 --raw-tail 50000

Endpoints:
    /           -> viz.html (the UI, next to this script)
    /api/data   -> JSON: condensed tally entries + parsed raw-tail records
    /api/events -> bounded pages of full lines from the retained raw log (loopback only)
    /api/recorded-events -> bounded searchable pages from the read-only event store (loopback only)
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import socketserver
import sqlite3
import sys
import base64
import hashlib
import urllib.parse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LOCAL_APPDATA = (os.environ.get("LOCALAPPDATA")
                 or os.path.expanduser(r"~\AppData\Local"))
DEFAULT_RAW_LOG = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "firewall.log")
DEFAULT_CONDENSED = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "condensed.json")
DEFAULT_RECOVERY_STATUS = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "recovery-status.json")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8780
DEFAULT_RAW_TAIL = 20000
EVENT_PAGE_DEFAULT = 100
EVENT_PAGE_MAX = 200
EVENT_PAGE_JSON_MAX = 1 << 20
EVENT_LINE_MAX = 128 << 10
EVENT_SCAN_MAX = 2 << 20
RECORDED_EVENT_PAGE_DEFAULT = 100
RECORDED_EVENT_PAGE_MAX = 200

FLOW_RE = re.compile(r"IP SRC=(\S+) IP DST=(\S+) IP proto=(\d+)(?: SPT=(\d+))?(?: DPT=(\d+))?")
AP_RE = re.compile(r"AP MAC=(\S+)")
PRI_RE = re.compile(r"^<(\d{1,3})>")

RFC1918_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
SYSLOG_FACILITIES = ["kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
                     "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
                     "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7"]
RFC5424_HEAD_RE = re.compile(
    r"^1\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$"
)
OMADA_V1_HEAD_RE = re.compile(
    r"^1\s+(\d{4}-\d\d-\d\d)\s+(\d\d:\d\d:\d\d)\s+"
    r"(\S+)\s+(\S+)\s+(\S+)\s+(\S+)(?:\s+(.*))?$"
)
RFC3164_HEAD_RE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"([A-Za-z0-9_.\-/]+)(?:\[(\d+)\])?:"
)
OMADA_WRAPPED_HEAD_RE = re.compile(
    r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+"
    r"([A-Za-z0-9_.\-/]+)<(\d+)>:\s*(.*)$"
)


def is_rfc1918(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in RFC1918_NETS)


def direction_of(src, dst):
    """Classify a flow by RFC1918 membership:
    internal (RFC1918 -> RFC1918), outbound (RFC1918 -> external),
    inbound (external -> RFC1918), other (anything else, incl. msgs)."""
    if not src or not dst:
        return "other"
    s, d = is_rfc1918(src), is_rfc1918(dst)
    if s and d:
        return "internal"
    if s and not d:
        return "outbound"
    if d and not s:
        return "inbound"
    return "other"


def _parse_structured_data_and_body(value):
    """Parse RFC5424 SD without losing the original representation."""
    if value is None:
        return None, [], False, ""
    if value == "-" or value.startswith("- "):
        return "-", [], True, value[2:] if value.startswith("- ") else ""
    if not value.startswith("["):
        return None, [], False, value
    elements = []
    i = 0
    while i < len(value) and value[i] == "[":
        start = i
        i += 1
        id_start = i
        while i < len(value) and value[i] not in " ]\t\r\n":
            i += 1
        sdid = value[id_start:i]
        params = []
        while i < len(value) and value[i] == " ":
            i += 1
            key_start = i
            while i < len(value) and value[i] not in "= ]\t\r\n":
                i += 1
            name = value[key_start:i]
            if not name or i >= len(value) or value[i] != "=":
                break
            i += 1
            if i >= len(value) or value[i] != '"':
                break
            i += 1
            out = []
            while i < len(value):
                c = value[i]
                i += 1
                if c == '"':
                    break
                if c == "\\" and i < len(value):
                    escaped = value[i]
                    i += 1
                    out.append(escaped if escaped in '"\\]' else "\\" + escaped)
                else:
                    out.append(c)
            params.append({"name": name, "value": "".join(out)})
        if i >= len(value) or value[i] != "]":
            return None, [], False, value
        i += 1
        elements.append({"id": sdid, "params": params, "raw": value[start:i]})
    if not elements:
        return None, [], False, value
    raw_sd = value[:i]
    body = value[i + 1:] if value[i:i + 1] == " " else value[i:]
    return raw_sd, elements, False, body


def _message_activity(body):
    """Conservative activity labels based on recognizable message wording."""
    text = body or ""
    variables = {}
    match = re.search(r"(?i)DHCP Server allocated IP address\s+([0-9a-f:.]+)\s+for the\s+\[client:([0-9a-f:-]+)\s*\]", text)
    if match:
        return {"id": "dhcp_allocation", "label": "DHCP address allocated",
                "variables": {"ip": match.group(1), "client_mac": match.group(2)},
                "sample_only": False, "coverage": "observed_message"}
    match = re.search(r"(?i)\[client:([0-9a-f:-]+)\]\s+is roaming from\s+\[ap:([0-9a-f:-]+)\](?:\[Channel\s+([^\]]+)\])?\s+to\s+\[ap:([0-9a-f:-]+)\](?:\[Channel\s+([^\]]+)\])?(?:\s+with SSID\s+(.+?))?(?:[.]|$)", text)
    if match:
        return {"id": "client_roaming", "label": "Client roaming",
                "variables": {"client_mac": match.group(1), "from_ap_mac": match.group(2),
                              "from_channel": match.group(3), "to_ap_mac": match.group(4),
                              "to_channel": match.group(5), "ssid": match.group(6)},
                "sample_only": False, "coverage": "observed_message"}
    match = re.search(r"(?i)client\s*[:=]?\s*([0-9a-f:-]{17}).*?disconnected from SSID\s+(.+?)\s+.*?connected(?: to)? SSID\s+(.+?)\s+.*?\bAP\b", text)
    if match:
        return {"id": "client_connection_transition", "label": "Client connection transition",
                "variables": {"client_mac": match.group(1), "from_ssid": match.group(2).strip(),
                              "to_ssid": match.group(3).strip()},
                "sample_only": False, "coverage": "observed_message"}
    return {"id": "unknown", "label": "Unclassified message", "variables": variables,
            "sample_only": False, "coverage": "observed_message"}


def _message_candidates(body):
    """Extract syntactically valid addresses and explicit key/value tokens."""
    result = []
    seen = set()
    def add(kind, value, role=None):
        key = (kind, value, role)
        if key not in seen:
            seen.add(key)
            entry = {"kind": kind, "value": value}
            if role:
                entry["role"] = role
            result.append(entry)
    for raw_token in re.findall(r"\S+", body or ""):
        token = raw_token.strip(".,;!?(){}<>\"'")
        token = re.sub(r"(?i)^(?:ip|src|dst|address)[:=]", "", token)
        if token.startswith("[") and "]" in token:
            token = token[1:token.index("]")]
        # IPv4 with an explicit port is common in prose; keep the address and
        # avoid treating the port as part of the candidate.
        ipv4_port = re.fullmatch(r"((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?", token)
        if ipv4_port:
            token = ipv4_port.group(1)
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        add("ip", token)
    for match in re.finditer(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])", body or ""):
        add("mac", match.group(0))
    for match in re.finditer(r"\b([A-Za-z][A-Za-z0-9_.-]{0,40})=([^\s\]]+)", body or ""):
        add("key_value", match.group(2), match.group(1))
    return result


def _sample_candidate_body(sample):
    """Return parsed syslog payload for a condenser sample, preserving fallback text."""
    try:
        parsed = parse_raw_line("2000-01-01T00:00:00Z\tcondensed-sample\t" + sample,
                                extract_message_details=False)
    except (TypeError, ValueError):
        return sample
    if parsed and parsed.get("type") == "msg":
        return parsed.get("message_body", sample)
    return sample


def tail_lines(path, limit):
    """Last `limit` lines of a text file (bounded backward read, no full-file IO)."""
    lines, _error = read_tail_lines(path, limit)
    return lines


def read_tail_lines(path, limit):
    """Return (lines, error) so an unavailable log differs from an empty one."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            if pos == 0:
                return [], None
            chunks = []
            nlines = 0
            while pos > 0 and nlines <= limit:
                step = min(1 << 20, pos)
                pos -= step
                f.seek(pos)
                data = f.read(step)
                chunks.append(data)
                nlines += data.count(b"\n")
            buf = b"".join(reversed(chunks))
            return buf.decode("utf-8", "replace").splitlines()[-limit:], None
    except OSError as e:
        return [], str(e)


def parse_raw_line(line, extract_message_details=True):
    """'ts\\tsender\\traw' -> compact record for the UI."""
    parts = line.split("\t", 2)
    if len(parts) != 3 or not parts[2]:
        return None
    ts, dev, raw = parts
    sev = None
    pri = None
    pm = PRI_RE.match(raw)
    if pm and int(pm.group(1)) <= 191:
        pri = int(pm.group(1))
        sev = pri % 8
    syslog_meta = {"sender": dev}
    message_body = raw
    if pri is not None:
        facility_id = pri // 8
        syslog_meta.update({"pri": pri, "facility_id": facility_id,
                            "facility": SYSLOG_FACILITIES[facility_id]})
        body = raw[pm.end():]
        if body.startswith("1 "):
            head = RFC5424_HEAD_RE.match(body)
            if head:
                timestamp, hostname, appname, procid, msgid, sd_and_msg = head.groups()
                if timestamp == "-" or re.match(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", timestamp):
                    structured, elements, nil, message_body = _parse_structured_data_and_body(sd_and_msg)
                    if hostname != "-":
                        syslog_meta["hostname"] = hostname
                    if appname != "-":
                        syslog_meta["tag"] = appname
                    if procid != "-":
                        syslog_meta["procid"] = procid
                    if msgid != "-":
                        syslog_meta["msgid"] = msgid
                    if structured is not None:
                        syslog_meta["structured_data"] = structured
                    if elements:
                        syslog_meta["structured_data_elements"] = elements
                    if nil:
                        syslog_meta["structured_data_nil"] = True
                    syslog_meta["syslog_format"] = "rfc5424"
            # Omada's observed v1 variant uses a space instead of RFC5424's T
            # between date and time. Parse it explicitly and retain the format.
            if "syslog_format" not in syslog_meta:
                omada = OMADA_V1_HEAD_RE.match(body)
                if omada:
                    date, clock, hostname, appname, procid, msgid, message_body = omada.groups()
                    if hostname != "-": syslog_meta["hostname"] = hostname
                    if appname != "-": syslog_meta["tag"] = appname
                    if procid != "-": syslog_meta["procid"] = procid
                    if msgid != "-": syslog_meta["msgid"] = msgid
                    syslog_meta["syslog_timestamp"] = date + " " + clock
                    syslog_meta["syslog_format"] = "omada-v1"
        else:
            head = RFC3164_HEAD_RE.match(body)
            if head:
                syslog_meta["hostname"] = head.group(4)
                syslog_meta["tag"] = head.group(5)
                if head.group(6):
                    syslog_meta["procid"] = head.group(6)
                message_body = body[head.end():].lstrip()
                syslog_meta["syslog_format"] = "rfc3164"
            else:
                omada_wrapped = OMADA_WRAPPED_HEAD_RE.match(body)
                if omada_wrapped:
                    month, day, clock, hostname, appname, inner_pri, message_body = omada_wrapped.groups()
                    syslog_meta.update({"hostname": hostname, "tag": appname,
                                        "inner_pri": int(inner_pri),
                                        "syslog_timestamp": "%s %s %s" % (month, day, clock),
                                        "syslog_format": "rfc3164-omada-wrapper"})
                else:
                    tag_wrapper = re.match(r"^([A-Za-z0-9_.\-/]+)<(\d+)>:\s*(.*)$", body)
                    if tag_wrapper:
                        appname, inner_pri, message_body = tag_wrapper.groups()
                        syslog_meta.update({"tag": appname, "inner_pri": int(inner_pri),
                                            "syslog_format": "omada-tag-wrapper"})
    m = FLOW_RE.search(raw)
    if m:
        rec = {"ts": ts, "src": m.group(1), "dst": m.group(2),
               "proto": int(m.group(3)),
               "dpt": int(m.group(5)) if m.group(5) else None,
               "sev": sev, "type": "flow",
               "dir": direction_of(m.group(1), m.group(2)),
               "label": "%s -> %s %s/%s" % (m.group(1), m.group(2),
                                            m.group(3), m.group(5) or "-")}
        if m.group(4):
            rec["spt"] = int(m.group(4))
        ap = AP_RE.search(raw)
        if ap:
            rec["ap"] = ap.group(1)
        rec.update(syslog_meta)
        return rec
    rec = {"ts": ts, "src": dev, "dst": None, "proto": None, "dpt": None,
           "sev": sev, "type": "msg", "dir": "other", "label": raw[:90],
           "message": raw, "message_body": message_body}
    if extract_message_details:
        rec["activity"] = _message_activity(message_body)
        rec["candidates"] = _message_candidates(message_body)
    rec.update(syslog_meta)
    return rec


def read_recovery_status(path):
    """Read the explicit condenser catch-up diagnostic without guessing from activity."""
    try:
        with open(path, encoding="utf-8") as f:
            status = json.load(f)
    except FileNotFoundError:
        return {"state": "unknown", "reason": "status_file_missing"}
    except OSError as e:
        return {"state": "unknown", "reason": "status_file_unreadable", "error": str(e)}
    except ValueError as e:
        return {"state": "unknown", "reason": "status_file_invalid", "error": str(e)}

    if (not isinstance(status, dict) or status.get("status") != "recovery_failed"
            or not isinstance(status.get("reason"), str)
            or not isinstance(status.get("updated_at"), str)):
        return {"state": "unknown", "reason": "status_file_invalid"}
    return {"state": "recovery_failed", "reason": status["reason"],
            "updated_at": status["updated_at"]}


class EventPageError(Exception):
    def __init__(self, status, message, **details):
        super().__init__(message)
        self.status = status
        self.details = details


def _event_snapshot(path, end=None):
    """Snapshot the retained prefix; later appends do not invalidate paging."""
    st = os.stat(path)
    end = st.st_size if end is None else end
    sample_len = min(128, end)
    with open(path, "rb") as f:
        if sample_len:
            f.seek(end - sample_len)
            sample = f.read(sample_len)
        else:
            sample = b""
    state = {"dev": st.st_dev, "ino": st.st_ino, "end": end,
             "sample_len": sample_len, "sample_sha256": hashlib.sha256(sample).hexdigest()}
    token = base64.urlsafe_b64encode(json.dumps(state, separators=(",", ":")).encode("ascii")).decode("ascii")
    return state, token


def _decode_event_snapshot(token):
    try:
        padded = token + "=" * (-len(token) % 4)
        state = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("ascii"))
        if (not isinstance(state, dict) or not isinstance(state.get("end"), int)
                or state["end"] < 0 or not isinstance(state.get("sample_len"), int)
                or state["sample_len"] < 0 or state["sample_len"] > 128
                or not isinstance(state.get("sample_sha256"), str)):
            raise ValueError("invalid snapshot")
        return state
    except (ValueError, UnicodeError, TypeError, json.JSONDecodeError) as e:
        raise EventPageError(400, "invalid event snapshot token") from e


def _event_raw_text(line):
    """Decode one retained line using the same replacement policy as the chart."""
    return line.decode("utf-8", "replace").rstrip("\r")


def read_event_page(path, limit=EVENT_PAGE_DEFAULT, before=None, snapshot=None):
    """Read a bounded newest-first page from the retained log, preserving every line."""
    if not isinstance(limit, int) or limit < 1 or limit > EVENT_PAGE_MAX:
        raise EventPageError(400, "limit must be between 1 and %d" % EVENT_PAGE_MAX)
    try:
        if snapshot is None:
            state, snapshot = _event_snapshot(path)
            before = state["end"] if before is None else before
        else:
            state = _decode_event_snapshot(snapshot)
            st = os.stat(path)
            if st.st_dev != state.get("dev") or st.st_ino != state.get("ino") or st.st_size < state["end"]:
                raise EventPageError(409, "retained log changed; refresh the event list")
            sample_len = state["sample_len"]
            with open(path, "rb") as f:
                if sample_len:
                    f.seek(state["end"] - sample_len)
                    sample = f.read(sample_len)
                else:
                    sample = b""
            if hashlib.sha256(sample).hexdigest() != state["sample_sha256"]:
                raise EventPageError(409, "retained log changed; refresh the event list")
            if before is None:
                before = state["end"]
        if not isinstance(before, int) or before < 0 or before > state["end"]:
            raise EventPageError(400, "before cursor is outside this log snapshot")
        if before == 0:
            return {"snapshot": snapshot, "before": 0, "next_before": None,
                    "has_older": False, "retained_bytes": state["end"], "events": [], "unparsed": 0}

        remaining = before
        pos = before
        scanned = 0
        chunks = []
        newline_count = 0
        with open(path, "rb") as f:
            while pos > 0 and newline_count <= limit and scanned < EVENT_SCAN_MAX:
                step = min(65536, pos, EVENT_SCAN_MAX - scanned)
                pos -= step
                f.seek(pos)
                chunk = f.read(step)
                chunks.insert(0, chunk)
                newline_count += chunk.count(b"\n")
                scanned += len(chunk)
        buf = b"".join(chunks)
        base = pos
        if base > 0:
            separator = buf.find(b"\n")
            if separator < 0:
                raise EventPageError(413, "a retained log line exceeds the 2 MiB scan limit")
            base += separator + 1
            buf = buf[separator + 1:]
        if buf:
            parts = buf.split(b"\n")
            terminal_newline = buf.endswith(b"\n")
            if terminal_newline:
                parts.pop()  # split sentinel, not a log record
            lines = []
            offset = base
            for i, part in enumerate(parts):
                line = part[:-1] if part.endswith(b"\r") else part
                lines.append((offset, line))
                offset += len(part) + (1 if i < len(parts) - 1 or terminal_newline else 0)
        else:
            lines = []
        selected = lines[-limit:]
        events = []
        encoded_size = 0
        for offset, line in reversed(selected):
            if len(line) > EVENT_LINE_MAX:
                raise EventPageError(413, "a retained log line exceeds the 128 KiB event limit",
                                     offset=offset, line_bytes=len(line), max_line_bytes=EVENT_LINE_MAX)
            text = _event_raw_text(line)
            parsed = parse_raw_line(text)
            parts = text.split("\t", 2)
            event = {"offset": offset, "timestamp": parsed.get("ts") if parsed else (parts[0] if len(parts) > 1 else None),
                     "sender": parsed.get("src") if parsed else (parts[1] if len(parts) > 1 else None),
                     "type": parsed.get("type") if parsed else "unparsed",
                     "parsed": parsed, "text": text}
            event_size = len(json.dumps(event, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
            if events and encoded_size + event_size > EVENT_PAGE_JSON_MAX:
                break
            if event_size > EVENT_PAGE_JSON_MAX:
                raise EventPageError(413, "a retained log line exceeds the 1 MiB response limit",
                                     offset=offset, max_response_bytes=EVENT_PAGE_JSON_MAX)
            events.append(event)
            encoded_size += event_size
        # Appends are expected and do not invalidate the fixed snapshot end.
        # Re-check the original prefix so a truncate/replace during the read is
        # reported instead of returning a mixed or skipped page.
        current, _token = _event_snapshot(path, end=state["end"])
        if (current["dev"] != state.get("dev") or current["ino"] != state.get("ino")
                or current["sample_sha256"] != state["sample_sha256"]):
            raise EventPageError(409, "retained log changed; refresh the event list")
        next_before = events[-1]["offset"] if events else None
        return {"snapshot": snapshot, "before": remaining, "next_before": next_before,
                "has_older": bool(next_before and next_before > 0),
                "retained_bytes": state["end"], "events": events,
                "unparsed": sum(event["type"] == "unparsed" for event in events)}
    except EventPageError:
        raise
    except OSError as e:
        raise EventPageError(503, str(e)) from e


def build_payload(args):
    out = {"generated": datetime.now().astimezone().isoformat(timespec="seconds"),
           "meta": {}, "entries": [], "raw": [], "sources": {}}
    out["recovery"] = read_recovery_status(
        getattr(args, "recovery_status_file", DEFAULT_RECOVERY_STATUS))
    try:
        with open(args.condense_file, encoding="utf-8") as f:
            state = json.load(f)
        if isinstance(state, dict):
            out["meta"] = state.pop("_meta", {})
            out["entries"] = []
            for v in state.values():
                if not isinstance(v, dict):
                    continue
                if v.get("type") == "flow":
                    v["dir"] = direction_of(v.get("src"), v.get("dst"))
                else:
                    v["dir"] = "other"
                    sample = v.get("sample")
                    has_sample = isinstance(sample, str) and sample != ""
                    candidate_body = _sample_candidate_body(sample) if has_sample else ""
                    evidence = candidate_body if has_sample else (v.get("template") or "")
                    activity = _message_activity(evidence)
                    activity["sample_only"] = True
                    activity["coverage"] = "single_sample" if has_sample else "template_only"
                    v["activity"] = activity
                    v["candidates"] = _message_candidates(candidate_body)
                    v["candidates_provenance"] = {
                        "sample_only": True,
                        "coverage": "single_sample" if has_sample else "no_sample"}
                out["entries"].append(v)
            out["sources"]["condensed"] = {"available": True, "entries": len(out["entries"])}
    except (OSError, ValueError) as e:
        out["condense_error"] = str(e)
        out["sources"]["condensed"] = {"available": False, "error": str(e)}
    recs = []
    lines, raw_error = read_tail_lines(args.log_file, args.raw_tail)
    for line in lines:
        rec = parse_raw_line(line)
        if rec:
            recs.append(rec)
    out["raw"] = recs
    out["sources"]["raw"] = ({"available": False, "error": raw_error}
                               if raw_error else {"available": True, "records": len(recs)})
    return out


def redact_remote_payload(payload):
    """Remove original message text fields from non-loopback chart responses.

    Condensed templates and parsed network/header metadata remain available to
    the chart; templates are patterns, not a promise of anonymization.
    """
    for entry in payload.get("entries", []):
        if entry.get("type") == "msg":
            entry.pop("sample", None)
            entry.pop("candidates", None)
            if isinstance(entry.get("activity"), dict):
                entry["activity"].pop("variables", None)
    for record in payload.get("raw", []):
        record.pop("structured_data", None)
        record.pop("structured_data_elements", None)
        if record.get("type") == "msg":
            record.pop("message", None)
            record.pop("message_body", None)
            record["label"] = "(message text hidden for remote clients)"
            record.pop("candidates", None)
            if isinstance(record.get("activity"), dict):
                record["activity"].pop("variables", None)
    return payload


def _local_host_header_allowed(value, configured_host=None, server_port=None):
    """Accept only localhost/loopback Host authorities for local sensitive APIs."""
    if not value or any(ord(ch) < 33 or ord(ch) == 127 for ch in value):
        return False
    try:
        parsed = urllib.parse.urlsplit("//" + value)
        if parsed.netloc != value or parsed.path or parsed.query or parsed.fragment:
            return False
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return False
    if not hostname or parsed.username is not None or parsed.password is not None:
        return False
    if port is not None and server_port is not None and port != server_port:
        return False
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost":
        return True
    try:
        if ipaddress.ip_address(normalized).is_loopback:
            return True
    except ValueError:
        pass
    if configured_host:
        configured = str(configured_host).strip().strip("[]").rstrip(".").lower()
        if configured not in ("", "0.0.0.0", "::", "*") and normalized == configured:
            return True
    return False


class VizServer(ThreadingHTTPServer):
    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            # mutually exclusive with the SO_REUSEADDR that TCPServer.server_bind
            # would set - set ours and do the bind ourselves
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            self.socket.bind(self.server_address)
        else:
            socketserver.TCPServer.server_bind(self)
        self.server_name = "omada-viz"   # skips HTTPServer.getfqdn (can hang on slow DNS)
        self.server_port = self.server_address[1]


class Handler(BaseHTTPRequestHandler):
    server_version = "OmadaViz/1.0"

    def _peer_is_local(self):
        try:
            return ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            return False

    def _local_host_is_allowed(self):
        configured_host = getattr(self.server.args, "host", None)
        port = getattr(self.server, "server_port", 0)
        if not port:
            listener = getattr(self.server, "socket", None)
            port = (listener.getsockname()[1] if listener is not None
                    else self.server.server_address[1])
        return _local_host_header_allowed(
            self.headers.get("Host"), configured_host, port)

    def do_GET(self):
        request = urllib.parse.urlsplit(self.path)
        if request.path in ("/", "/index.html"):
            self._serve_file(os.path.join(self.server.args.html_dir, "viz.html"),
                             "text/html; charset=utf-8")
        elif request.path == "/favicon.ico":
            self._send(204, "image/x-icon", b"")
        elif request.path == "/api/events":
            if not self._peer_is_local():
                self._send(403, "application/json", json.dumps({"error": "event browsing is available on localhost only"}).encode("utf-8"))
                return
            if not self._local_host_is_allowed():
                self._send(403, "application/json", json.dumps({"error": "event browsing requires a localhost Host header"}).encode("utf-8"))
                return
            query = urllib.parse.parse_qs(request.query, keep_blank_values=True)
            try:
                limit = int(query.get("limit", [str(EVENT_PAGE_DEFAULT)])[0])
                before_value = query.get("before", [None])[0]
                before = int(before_value) if before_value not in (None, "") else None
                snapshot = query.get("snapshot", [None])[0]
                result = read_event_page(self.server.args.log_file, limit, before, snapshot)
                self._send(200, "application/json", json.dumps(result).encode("utf-8"))
            except ValueError:
                self._send(400, "application/json", json.dumps({"error": "invalid page limit or cursor"}).encode("utf-8"))
            except EventPageError as e:
                body = {"error": str(e), **e.details}
                self._send(e.status, "application/json", json.dumps(body).encode("utf-8"))
        elif request.path == "/api/recorded-events":
            if not self._peer_is_local():
                self._send(403, "application/json", json.dumps({"error": "recorded event search is available on localhost only"}).encode("utf-8"))
                return
            if not self._local_host_is_allowed():
                self._send(403, "application/json", json.dumps({"error": "recorded event search requires a localhost Host header"}).encode("utf-8"))
                return
            self._serve_recorded_events(request.query)
        elif request.path == "/api/data":
            peer_is_local = self._peer_is_local()
            if peer_is_local and not self._local_host_is_allowed():
                self._send(403, "application/json", json.dumps({"error": "local data access requires a localhost Host header"}).encode("utf-8"))
                return
            payload = build_payload(self.server.args)
            if not peer_is_local:
                redact_remote_payload(payload)
            body = json.dumps(payload).encode("utf-8")
            self._send(200, "application/json", body)
        else:
            self._send(404, "text/plain", b"not found")

    def _serve_recorded_events(self, query_string):
        """Serve a bounded page from the local event store without opening it for writes."""
        from omada_event_store import default_event_path, event_status, query_events

        query = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        allowed = {"type", "kind", "activity", "ip", "mac", "since", "until", "sender", "q", "limit", "cursor", "sort"}
        if set(query) - allowed or any(len(values) != 1 for values in query.values()):
            self._send(400, "application/json", json.dumps({"error": "unsupported or repeated query parameter"}).encode("utf-8"))
            return
        values = {key: items[0] for key, items in query.items()}
        kind = values.get("type", values.get("kind", "all"))
        if "type" in values and "kind" in values:
            self._send(400, "application/json", json.dumps({"error": "use only one of type or kind"}).encode("utf-8"))
            return
        if kind not in ("all", "dhcp"):
            self._send(400, "application/json", json.dumps({"error": "type must be all or dhcp"}).encode("utf-8"))
            return
        try:
            limit = int(values.get("limit", RECORDED_EVENT_PAGE_DEFAULT))
            if limit < 1 or limit > RECORDED_EVENT_PAGE_MAX:
                raise ValueError("limit must be between 1 and %d" % RECORDED_EVENT_PAGE_MAX)
            activity = values.get("activity") or None
            if kind == "dhcp":
                if activity and activity != "dhcp_allocation":
                    raise ValueError("kind=dhcp cannot be combined with a non-DHCP activity")
                activity = "dhcp_allocation"
            sort = values.get("sort", "received_at_desc")
            path = (getattr(self.server.args, "event_file", None)
                    or default_event_path(self.server.args.log_file))
            try:
                status = event_status(path)
            except (OSError, sqlite3.Error, ValueError, TypeError, KeyError):
                self._send(503, "application/json", json.dumps({
                    "error": "event store status is unreadable",
                    "status": {"state": "error"},
                }).encode("utf-8"))
                return
            if status.get("state") == "unavailable":
                self._send(200, "application/json", json.dumps({
                    "status": status, "events": [], "next_cursor": None,
                    "note": "The event store is unavailable; no search results are being reported as empty history.",
                }).encode("utf-8"))
                return
            result = query_events(
                path, limit=limit, cursor=values.get("cursor") or None,
                ip=values.get("ip") or None, mac=values.get("mac") or None,
                activity=activity, text=values.get("q") or None,
                since=values.get("since") or None, until=values.get("until") or None,
                source=values.get("sender") or None, sort=sort,
            )
            events = []
            for item in result.get("items", []):
                event = {
                    "id": item.get("id"),
                    "timestamp": item.get("received_at"),
                    "sender": item.get("source"),
                    "client_mac": item.get("mac"),
                    "allocated_ip": item.get("ip"),
                    "source_event": item.get("raw"),
                    "activity": item.get("activity"),
                    "parse_status": item.get("parse_status"),
                    "origin": item.get("origin"),
                    "metadata": item.get("metadata") or {},
                }
                if item.get("raw_base64") is not None:
                    event["source_event_base64"] = item["raw_base64"]
                events.append(event)
            payload = {"status": status, "events": events,
                       "next_cursor": result.get("next_cursor"),
                       "limit": limit}
            if any(event.get("activity") == "dhcp_allocation" for event in events):
                payload["interpretation"] = "DHCP allocation observations are historical records and do not indicate an active lease."
            self._send(200, "application/json", json.dumps(payload).encode("utf-8"))
        except ValueError as e:
            self._send(400, "application/json", json.dumps({"error": str(e)}).encode("utf-8"))
        except sqlite3.Error:
            self._send(503, "application/json", json.dumps({"error": "event store is busy or unreadable", "status": {"state": "error"}}).encode("utf-8"))

    def _serve_file(self, path, ctype):
        try:
            with open(path, "rb") as f:
                self._send(200, ctype, f.read())
        except OSError:
            self._send(404, "text/plain", b"viz.html not found next to omada_viz.py")

    def _send(self, code, ctype, body):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *a):
        pass  # keep the console clean


def main(argv=None):
    p = argparse.ArgumentParser(prog="omada_viz", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default=DEFAULT_HOST,
                   help="bind address (default: %(default)s)")
    p.add_argument("--port", type=int, default=DEFAULT_PORT,
                   help="port (default: %(default)s)")
    p.add_argument("--condense-file", default=DEFAULT_CONDENSED,
                   help="condensed tallies file (default: %(default)s)")
    p.add_argument("--log-file", default=DEFAULT_RAW_LOG,
                   help="raw log file (default: %(default)s)")
    p.add_argument("--event-file", default=None,
                   help="SQLite event history (default: next to the raw log)")
    p.add_argument("--raw-tail", type=int, default=DEFAULT_RAW_TAIL,
                   help="max raw records served (default: %(default)s)")
    args = p.parse_args(argv)
    if args.event_file is None:
        from omada_event_store import default_event_path
        args.event_file = default_event_path(args.log_file)
    args.html_dir = os.path.dirname(os.path.abspath(__file__))
    srv = VizServer((args.host, args.port), Handler)
    srv.args = args
    print("omada viz: http://%s:%d  (Ctrl+C to stop)" % (args.host, args.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("bye", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
