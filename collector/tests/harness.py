"""Test harness for the collector: mock IP providers + the real central service (with a mock Cloudflare).

Usage: python harness.py <info.json>   (runs until killed / stdin closes)
"""
import json
import os
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "server"))
sys.path.insert(0, os.path.join(ROOT, "server", "tests"))

from mockcf import ACCOUNT, NTFY_TOKEN, TOKEN, ZT_LIST, MockServer  # noqa: E402

from cfip.cloudflare import make_backend  # noqa: E402
from cfip.config import Config  # noqa: E402
from cfip.notify import Notifier  # noqa: E402
from cfip.server import App, serve  # noqa: E402
from cfip.store import Store  # noqa: E402
from cfip.sync import Syncer  # noqa: E402

PROVIDERS = {"/ip/good": (200, "9.9.9.9\n"), "/ip/good2": (200, "149.112.112.112"), "/ip/changed": (200, "1.1.1.1"),
             "/ip/private": (200, "10.1.2.3"), "/ip/cgnat": (200, "100.64.0.5"), "/ip/doc": (200, "203.0.113.9"),
             "/ip/garbage": (200, "<html>nope</html>"), "/ip/v6": (200, "2001:4860:4860::8888"),
             "/ip/multi": (200, "9.9.9.9 1.1.1.1"), "/ip/leading0": (200, "09.9.9.9"), "/ip/500": (500, "err"),
             "/report500": (500, '{"ok":false}'), "/report400": (400, '{"ok":false}')}


class P(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _go(self):
        if self.path == "/ip/slow":
            time.sleep(6)
        code, body = PROVIDERS.get(self.path, (404, "nf"))
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass  # the collector timed out on /ip/slow, as intended

    do_GET = _go
    do_POST = _go


def main():
    mock = MockServer()
    prov = ThreadingHTTPServer(("127.0.0.1", 0), P)
    threading.Thread(target=prov.serve_forever, daemon=True).start()
    data = tempfile.mkdtemp(prefix="cfip-harness-")
    env = {"CF_API_TOKEN": TOKEN, "CF_ACCOUNT_ID": ACCOUNT, "CF_LIST_ID": ZT_LIST, "CF_API_BASE": mock.base,
           "NTFY_URL": mock.ntfy_url, "NTFY_TOKEN": NTFY_TOKEN, "DATA_DIR": data, "LISTEN_HOST": "127.0.0.1",
           "LISTEN_PORT": "0", "TRUSTED_PROXIES": "10.23.23.176", "STATIC_ALLOWLIST": "BCT-Office=8.8.4.4"}
    cfg = Config.from_env(env)
    store = Store(data)
    token = store.add_client("ACME", "Acme Pty Ltd")
    notifier = Notifier(cfg.ntfy_url, cfg.ntfy_token)
    app = App(cfg, store, notifier, Syncer(cfg, store, make_backend(cfg), notifier))
    httpd = serve(app, run_loop=False)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    info = {"report_url": f"http://127.0.0.1:{httpd.server_address[1]}/report",
            "providers": f"http://127.0.0.1:{prov.server_address[1]}", "token": token, "data_dir": data}
    tmp = sys.argv[1] + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(info, fh)
    os.replace(tmp, sys.argv[1])
    try:
        sys.stdin.read()  # block until the test closes stdin / kills us
    finally:
        httpd.shutdown()
        prov.shutdown()
        mock.close()


if __name__ == "__main__":
    main()
