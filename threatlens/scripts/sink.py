"""A stand-in for SIEMs, TIPs and chat webhooks, for trying Argus integrations
without them (docs/INTEGRATIONS.md). Every request is printed and appended to
a JSON-lines file; the answer has the shape the real product returns:

    POST /services/collector/event   Splunk HEC     {"text": "Success", "code": 0}
    POST /_bulk                      Elastic        {"errors": false, "items": [...]}
    GET  /                           Elastic        {"version": {"number": "sink"}}
    POST /events/add                 MISP           {"Event": {"id": "<n>"}}
    GET  /servers/getVersion         MISP           {"version": "sink"}
    POST anything else               webhook/Slack  {"ok": true}

usage: python scripts/sink.py [port] [log file]   (default 8099, sink.jsonl)
Point an integration at http://127.0.0.1:8099 with "internal network" ticked;
the Argus server needs TL_ALLOW_LOOPBACK_DESTINATIONS=true for 127.0.0.1.
Development only: it listens on 127.0.0.1 and trusts everything.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8099
LOG = Path(sys.argv[2] if len(sys.argv) > 2 else "sink.jsonl")
_events = [0]


class Sink(BaseHTTPRequestHandler):
    def _answer(self, body: object, status: int = 200) -> None:
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _record(self, body: bytes) -> None:
        auth = self.headers.get("Authorization", "")
        entry = {
            "method": self.command,
            "path": self.path,
            # the scheme only (Splunk, ApiKey, Bearer); a bare key (MISP) becomes ***
            "auth": ((auth.split(" ")[0] + " ***") if " " in auth else "***") if auth else None,
            "content_type": self.headers.get("Content-Type"),
            "bytes": len(body),
            "body": body.decode("utf-8", "replace")[:4000],
        }
        with LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"{self.command} {self.path} {len(body)} bytes auth={entry['auth']}", flush=True)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        self._record(b"")
        if self.path.startswith("/servers/getVersion"):
            self._answer({"version": "sink"})
        else:
            self._answer({"version": {"number": "sink"}, "tagline": "Argus integration sink"})

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self._record(body)
        if self.path.startswith("/services/collector"):
            self._answer({"text": "Success", "code": 0})
        elif self.path.startswith("/_bulk"):
            n = len(body.splitlines()) // 2
            self._answer({"errors": False, "items": [{"index": {"status": 201}}] * n})
        elif self.path.startswith("/events/add"):
            _events[0] += 1
            self._answer({"Event": {"id": str(_events[0])}})
        else:
            self._answer({"ok": True})

    def log_message(self, *args: object) -> None:  # quiet: _record prints one line
        return


if __name__ == "__main__":
    print(f"sink on http://127.0.0.1:{PORT}, logging to {LOG.resolve()}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Sink).serve_forever()
