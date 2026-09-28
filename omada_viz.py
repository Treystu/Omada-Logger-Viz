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
"""

import argparse
import ipaddress
import json
import os
import re
import socket
import socketserver
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_LOCAL_APPDATA = (os.environ.get("LOCALAPPDATA")
                 or os.path.expanduser(r"~\AppData\Local"))
DEFAULT_RAW_LOG = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "firewall.log")
DEFAULT_CONDENSED = os.path.join(_LOCAL_APPDATA, "OmadaSyslog", "condensed.json")
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8780
DEFAULT_RAW_TAIL = 20000

FLOW_RE = re.compile(r"IP SRC=(\S+) IP DST=(\S+) IP proto=(\d+)(?: SPT=(\d+))?(?: DPT=(\d+))?")
PRI_RE = re.compile(r"^<(\d{1,3})>")

RFC1918_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


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


def tail_lines(path, limit):
    """Last `limit` lines of a text file (bounded backward read, no full-file IO)."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            pos = f.tell()
            if pos == 0:
                return []
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
            return buf.decode("utf-8", "replace").splitlines()[-limit:]
    except OSError:
        return []


def parse_raw_line(line):
    """'ts\\tsender\\traw' -> compact record for the UI."""
    parts = line.split("\t", 2)
    if len(parts) != 3 or not parts[2]:
        return None
    ts, dev, raw = parts
    sev = None
    pm = PRI_RE.match(raw)
    if pm and int(pm.group(1)) <= 191:
        sev = int(pm.group(1)) % 8
    m = FLOW_RE.search(raw)
    if m:
        return {"ts": ts, "src": m.group(1), "dst": m.group(2),
                "proto": int(m.group(3)),
                "dpt": int(m.group(5)) if m.group(5) else None,
                "sev": sev, "type": "flow",
                "dir": direction_of(m.group(1), m.group(2)),
                "label": "%s -> %s %s/%s" % (m.group(1), m.group(2),
                                             m.group(3), m.group(5) or "-")}
    return {"ts": ts, "src": dev, "dst": None, "proto": None, "dpt": None,
            "sev": sev, "type": "msg", "dir": "other", "label": raw[:90]}


def build_payload(args):
    out = {"generated": datetime.now().astimezone().isoformat(timespec="seconds"),
           "meta": {}, "entries": [], "raw": []}
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
                out["entries"].append(v)
    except (OSError, ValueError) as e:
        out["condense_error"] = str(e)
    recs = []
    for line in tail_lines(args.log_file, args.raw_tail):
        rec = parse_raw_line(line)
        if rec:
            recs.append(rec)
    out["raw"] = recs
    return out


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

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_file(os.path.join(self.server.args.html_dir, "viz.html"),
                             "text/html; charset=utf-8")
        elif self.path == "/favicon.ico":
            self._send(204, "image/x-icon", b"")
        elif self.path.startswith("/api/data"):
            body = json.dumps(build_payload(self.server.args)).encode("utf-8")
            self._send(200, "application/json", body)
        else:
            self._send(404, "text/plain", b"not found")

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
    p.add_argument("--raw-tail", type=int, default=DEFAULT_RAW_TAIL,
                   help="max raw records served (default: %(default)s)")
    args = p.parse_args(argv)
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
