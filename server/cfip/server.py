"""HTTP report endpoint + hourly sync loop (stdlib only).

POST /report   Authorization: Bearer <client token>   {"client":"ACME","ip":"x.x.x.x","hostname":"..","version":".."}
GET  /healthz  liveness + last sync summary (no secrets, no client IPs)
"""
from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .reports import handle_report, observed_ip

log = logging.getLogger("cfip.server")
MAX_BODY = 4096
FAIL_WINDOW, FAIL_LIMIT = 600, 10


class App:
    def __init__(self, cfg, store, notifier, syncer):
        self.cfg, self.store, self.notifier, self.syncer = cfg, store, notifier, syncer
        self.sync_now = threading.Event()
        self.stop = threading.Event()
        self.failures: dict[str, list[float]] = {}
        self.flock = threading.Lock()

    def throttled(self, ip: str) -> bool:
        with self.flock:
            t = time.time()
            self.failures[ip] = [x for x in self.failures.get(ip, []) if t - x < FAIL_WINDOW]
            return len(self.failures[ip]) >= FAIL_LIMIT

    def record_failure(self, ip: str) -> None:
        with self.flock:
            self.failures.setdefault(ip, []).append(time.time())

    def loop(self) -> None:
        next_run = 0.0
        while not self.stop.is_set():
            if time.time() >= next_run or self.sync_now.is_set():
                self.sync_now.clear()
                try:
                    self.syncer.run()
                except Exception:  # keep the loop alive; the error is alerted inside run()/here
                    log.exception("sync crashed")
                    self.notifier.send("sync crashed", "Unexpected error in sync loop; see container logs.", 5)
                next_run = time.time() + self.cfg.sync_interval
            self.sync_now.wait(timeout=min(30, max(1, next_run - time.time())))


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "dx-cfip/" + __version__
        sys_version = ""

        def log_message(self, fmt, *args):  # never log headers (tokens)
            log.debug("%s %s", self.address_string(), fmt % args)

        def _send(self, status: int, obj: dict) -> None:
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path.split("?")[0] == "/healthz":
                ls = {k: v for k, v in app.store.state().get("last_sync", {}).items() if k != "error"}
                return self._send(200, {"ok": True, "version": __version__, "last_sync": ls,
                                        "list_kind": app.cfg.cf_list_kind, "dry_run": app.cfg.dry_run})
            return self._send(404, {"ok": False, "error": "not found"})

        def do_POST(self):
            if self.path.split("?")[0] != "/report":
                return self._send(404, {"ok": False, "error": "not found"})
            src = observed_ip(app.cfg, self.client_address[0], self.headers.get("X-Forwarded-For"))
            if app.throttled(src):
                return self._send(429, {"ok": False, "error": "too many failed attempts"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = -1
            if length <= 0 or length > MAX_BODY:
                return self._send(400, {"ok": False, "error": "bad body length"})
            try:
                body = json.loads(self.rfile.read(length))
                if not isinstance(body, dict):
                    raise ValueError
            except ValueError:
                return self._send(400, {"ok": False, "error": "invalid json"})
            auth = self.headers.get("Authorization") or ""
            token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
            status, resp, changed = handle_report(app.cfg, app.store, app.notifier, body, token,
                                                  self.client_address[0], self.headers.get("X-Forwarded-For"))
            if status == 401:
                app.record_failure(src)
            if changed and app.cfg.sync_on_change:
                app.sync_now.set()
            return self._send(status, resp)

    return Handler


def serve(app: App, run_loop: bool = True) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((app.cfg.listen_host, app.cfg.listen_port), make_handler(app))
    httpd.daemon_threads = True
    if run_loop:
        threading.Thread(target=app.loop, name="sync-loop", daemon=True).start()
    return httpd
