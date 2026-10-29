import json
import threading
import time
import urllib.error
import urllib.request

import pytest

from cfip.server import App, serve


@pytest.fixture
def server(ctx_factory):
    started = []

    def start(run_loop=False, **extra):
        c = ctx_factory(LISTEN_PORT=0, **extra)
        c.cfg.listen_port = 0
        app = App(c.cfg, c.store, c.notifier, c.syncer)
        httpd = serve(app, run_loop=run_loop)
        threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        started.append((app, httpd))
        c.app = app
        c.url = f"http://127.0.0.1:{httpd.server_address[1]}"
        return c
    yield start
    for app, httpd in started:
        app.stop.set()
        httpd.shutdown()


def post(url, body, token=None, xff=None, raw=None):
    data = raw if raw is not None else json.dumps(body).encode()
    req = urllib.request.Request(url + "/report", data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    if token is not None:
        req.add_header("Authorization", "Bearer " + token)
    if xff:
        req.add_header("X-Forwarded-For", xff)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def test_good_token_records_observed_ip_from_xff(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme")
    st, body = post(c.url, {"client": "acme", "ip": "1.1.1.1"}, tok, xff="9.9.9.9")
    assert st == 200 and body["status"] == "new" and body["ip"] == "9.9.9.9"
    s = c.store.state()["clients"]["ACME"]
    assert s["ip"] == "9.9.9.9" and s["reported_ip"] == "1.1.1.1"
    # mismatch between observed and reported raises a (single) p4 alert
    assert [n["priority"] for n in c.mock.s.ntfy if "mismatch" in n["title"]] == [4]
    assert c.app.sync_now.is_set()


def test_bad_token_unknown_client_and_missing_token(server):
    c = server()
    c.store.add_client("ACME", "Acme")
    assert post(c.url, {"client": "ACME", "ip": "1.1.1.1"}, "wrong")[0] == 401
    assert post(c.url, {"client": "NOPE", "ip": "1.1.1.1"}, "wrong")[0] == 401
    assert post(c.url, {"client": "ACME", "ip": "1.1.1.1"})[0] == 401
    assert "ACME" not in c.store.state()["clients"]


def test_token_of_other_client_rejected(server):
    c = server()
    c.store.add_client("ACME", "Acme")
    beta = c.store.add_client("BETA", "Beta")
    assert post(c.url, {"client": "ACME", "ip": "1.1.1.1"}, beta, xff="9.9.9.9")[0] == 401


def test_disabled_client_rejected(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme")
    c.store.set_client("ACME", disabled=True)
    assert post(c.url, {"client": "ACME"}, tok, xff="9.9.9.9")[0] == 401


def test_bruteforce_throttled(server):
    c = server()
    c.store.add_client("ACME", "Acme")
    codes = [post(c.url, {"client": "ACME"}, "bad", xff="9.9.9.9")[0] for _ in range(11)]
    assert codes[:10] == [401] * 10 and codes[10] == 429


def test_xff_ignored_from_untrusted_peer_falls_back_to_reported(server):
    c = server(TRUSTED_PROXIES="10.23.23.176")
    tok = c.store.add_client("ACME", "Acme")
    st, body = post(c.url, {"client": "ACME", "ip": "1.1.1.1"}, tok, xff="9.9.9.9")
    # peer 127.0.0.1 is not NPM -> XFF ignored; observed is private -> reported public IP is used
    assert st == 200 and body["observed_ip"] == "127.0.0.1" and body["ip"] == "1.1.1.1"


def test_spoofed_xff_prefix_does_not_win(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme")
    # client sends its own XFF "6.6.6.6"; NPM appends the real source 9.9.9.9 -> right-most wins
    st, body = post(c.url, {"client": "ACME"}, tok, xff="6.6.6.6, 9.9.9.9")
    assert body["ip"] == "9.9.9.9"


def test_ip_source_client_mode(server):
    c = server(IP_SOURCE="client")
    tok = c.store.add_client("ACME", "Acme")
    assert post(c.url, {"client": "ACME", "ip": "1.1.1.1"}, tok, xff="9.9.9.9")[1]["ip"] == "1.1.1.1"


def test_no_public_ip_rejected(server):
    c = server(TRUSTED_PROXIES="10.23.23.176")
    tok = c.store.add_client("ACME", "Acme")
    assert post(c.url, {"client": "ACME", "ip": "192.168.1.5"}, tok)[0] == 422


def test_allowed_cidrs_enforced(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme", ["9.9.9.0/24"])
    assert post(c.url, {"client": "ACME"}, tok, xff="9.9.9.9")[0] == 200
    assert post(c.url, {"client": "ACME"}, tok, xff="8.8.8.8")[0] == 403
    assert c.mock.s.ntfy[-1]["priority"] == 5
    assert c.store.state()["clients"]["ACME"]["ip"] == "9.9.9.9"


def test_heartbeat_unchanged_and_change(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme")
    post(c.url, {"client": "ACME"}, tok, xff="9.9.9.9")
    c.app.sync_now.clear()
    st, body = post(c.url, {"client": "ACME"}, tok, xff="9.9.9.9")
    assert body["status"] == "unchanged" and not c.app.sync_now.is_set()
    st, body = post(c.url, {"client": "ACME"}, tok, xff="9.9.9.10")
    assert body["status"] == "changed" and c.app.sync_now.is_set()
    assert c.store.state()["clients"]["ACME"]["previous_ip"] == "9.9.9.9"


def test_flapping_ip_quarantined_until_approved(server):
    import os

    from cfip.__main__ import main
    c = server(MAX_IP_CHANGES_PER_DAY=2)
    tok = c.store.add_client("ACME", "Acme")
    for ip in ("9.9.9.1", "9.9.9.2", "9.9.9.3"):
        post(c.url, {"client": "ACME"}, tok, xff=ip)
    st, body = post(c.url, {"client": "ACME"}, tok, xff="9.9.9.4")
    assert body["status"] == "quarantined"
    s = c.store.state()["clients"]["ACME"]
    assert s["ip"] == "9.9.9.3" and s["pending_ip"] == "9.9.9.4"
    assert any("QUARANTINED" in n["title"] and n["priority"] == 5 for n in c.mock.s.ntfy)
    os.environ["DATA_DIR"] = c.cfg.data_dir
    try:
        assert main(["client", "approve", "ACME"]) == 0
    finally:
        del os.environ["DATA_DIR"]
    assert c.store.state()["clients"]["ACME"]["ip"] == "9.9.9.4"


def test_bad_bodies(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme")
    assert post(c.url, None, tok, raw=b"not json")[0] == 400
    assert post(c.url, None, tok, raw=b"[1,2]")[0] == 400
    assert post(c.url, None, tok, raw=b"x" * 5000)[0] == 400


def test_healthz_has_no_secrets(server):
    c = server()
    with urllib.request.urlopen(c.url + "/healthz", timeout=5) as r:
        text = r.read().decode()
    assert '"ok": true' in text and "test-cf-token" not in text and "test-ntfy-token" not in text


def test_end_to_end_report_triggers_sync(server):
    c = server(run_loop=True)
    tok = c.store.add_client("ACME", "Acme")
    deadline = time.time() + 5
    while time.time() < deadline and not c.store.state().get("last_sync"):
        time.sleep(0.05)  # initial sync on startup (adds static entry)
    post(c.url, {"client": "ACME"}, tok, xff="9.9.9.9")
    deadline = time.time() + 5
    while time.time() < deadline and "9.9.9.9" not in c.items():
        time.sleep(0.05)
    assert c.items().get("9.9.9.9") == "dx-cfip:ACME Acme"
    assert "203.0.113.10" in c.items()


def test_null_ip_from_collector_uses_observed(server):
    c = server()
    tok = c.store.add_client("ACME", "Acme")
    st, body = post(c.url, {"client": "ACME", "ip": None}, tok, xff="9.9.9.9")
    assert st == 200 and body["ip"] == "9.9.9.9"
    assert c.store.state()["clients"]["ACME"]["reported_ip"] is None
