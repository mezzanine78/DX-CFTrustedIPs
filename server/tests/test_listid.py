"""CF_LIST_ID validation / name resolution, path quoting, and ntfy failure logging."""
import logging

import pytest
from mockcf import ACCOUNT, NTFY_TOKEN, RULES_LIST, TOKEN, ZT_LIST

from cfip.__main__ import main
from cfip.cloudflare import CloudflareError, ListLookupError, RulesList, ZeroTrustList, looks_like_list_id, seg
from cfip.config import ConfigError
from cfip.notify import Notifier


def zt(mock, list_id):
    return ZeroTrustList(mock.base, TOKEN, ACCOUNT, list_id, timeout=5)


def rules(mock, list_id):
    return RulesList(mock.base, TOKEN, ACCOUNT, list_id, timeout=5, poll_seconds=5)


def lookups(mock):
    return [p for m, p in mock.s.requests if p.endswith(("/gateway/lists", "/rules/lists"))]


def test_looks_like_list_id():
    assert looks_like_list_id(ZT_LIST) and looks_like_list_id(ZT_LIST.upper()) and looks_like_list_id("b" * 32)
    for bad in ("DX trusted client IPs", "", "b" * 31, ZT_LIST + "x", "g" * 32):
        assert not looks_like_list_id(bad)


def test_uuid_passthrough_no_lookup(mock):
    b = zt(mock, ZT_LIST)
    assert b.resolve_list_id() == ZT_LIST
    assert b.list_items() == []
    assert lookups(mock) == []


def test_hex32_passthrough_no_lookup(mock):
    b = rules(mock, RULES_LIST)
    assert b.resolve_list_id() == RULES_LIST
    assert b.list_items() == []
    assert lookups(mock) == []


def test_zerotrust_name_resolved_and_cached(mock, caplog):
    caplog.set_level(logging.INFO, "cfip")
    b = zt(mock, "DX trusted client IPs")
    b.list_items()
    b.list_items()
    assert b.resolve_list_id() == ZT_LIST
    assert len(lookups(mock)) == 1  # cached for the run
    assert f'Resolved CF_LIST_ID name "DX trusted client IPs" to {ZT_LIST}' in caplog.text
    assert all(" " not in p for p in mock.s.raw_paths)


def test_name_case_insensitive_trimmed(mock):
    assert zt(mock, "  dx TRUSTED client ips ").resolve_list_id() == ZT_LIST


def test_exact_match_wins_over_casefold(mock):
    other = "11111111-2222-4333-8444-555555555555"
    mock.s.zt_lists.append({"id": other, "name": "dx trusted client ips", "type": "IP"})
    assert zt(mock, "dx trusted client ips").resolve_list_id() == other
    assert zt(mock, "DX trusted client IPs").resolve_list_id() == ZT_LIST


def test_rules_name_resolved(mock):
    b = rules(mock, "dx_trusted_client_ips")
    assert b.list_items() == []
    assert b.resolve_list_id() == RULES_LIST


def test_no_match_message(mock):
    with pytest.raises(ListLookupError) as ei:
        zt(mock, "Nope list").resolve_list_id()
    msg = str(ei.value)
    assert "Nope list" in msg and "copy the ID from the end of the URL" in msg and "CF_LIST_ID" in msg
    assert "'DX trusted client IPs'" in msg and "'Blocked domains'" in msg
    assert isinstance(ei.value, ConfigError) and isinstance(ei.value, CloudflareError)


def test_ambiguous_match(mock):
    mock.s.zt_lists.append({"id": "11111111-2222-4333-8444-555555555555", "name": "Dup", "type": "IP"})
    mock.s.zt_lists.append({"id": "22222222-2222-4333-8444-555555555555", "name": "Dup", "type": "IP"})
    with pytest.raises(ListLookupError) as ei:
        zt(mock, "Dup").resolve_list_id()
    assert "matches 2" in str(ei.value) and "11111111-" in str(ei.value) and "22222222-" in str(ei.value)


def test_ambiguous_across_types_prefers_ip(mock):
    mock.s.zt_lists.append({"id": "33333333-2222-4333-8444-555555555555", "name": "Mixed", "type": "DOMAIN"})
    mock.s.zt_lists.append({"id": "44444444-2222-4333-8444-555555555555", "name": "Mixed", "type": "IP"})
    assert zt(mock, "Mixed").resolve_list_id().startswith("44444444")


def test_non_ip_list_rejected(mock):
    with pytest.raises(ListLookupError, match="type DOMAIN"):
        zt(mock, "Blocked domains").resolve_list_id()


def test_sync_with_unknown_name_fails_cleanly(ctx_factory):
    c = ctx_factory(CF_LIST_ID="No such list")
    res = c.syncer.run()
    assert not res.ok and "copy the ID" in res.error
    assert c.mock.s.ntfy[-1]["priority"] == 5


def test_sync_with_name_works_end_to_end(ctx_factory):
    c = ctx_factory(CF_LIST_ID="DX trusted client IPs")
    c.set_client_ip("ACME", "198.51.100.7", "Acme")
    c.set_client_ip("BETA", "198.51.100.8", "Beta")
    assert c.syncer.run().ok
    assert "198.51.100.7" in c.items()


def test_cli_unknown_name_exit_2(ctx_factory, monkeypatch, capsys):
    c = ctx_factory(CF_LIST_ID="No such list")
    for k, v in c.env.items():
        monkeypatch.setenv(k, v)
    assert main(["sync", "--dry-run"]) == 2
    err = capsys.readouterr().err
    assert "config error" in err and "copy the ID" in err and TOKEN not in err


def test_cli_name_resolves_at_startup(ctx_factory, monkeypatch, capsys, caplog):
    caplog.set_level(logging.INFO, "cfip")
    c = ctx_factory(CF_LIST_ID="DX trusted client IPs")
    for k, v in c.env.items():
        monkeypatch.setenv(k, v)
    assert main(["sync", "--dry-run"]) == 0
    assert "Resolved CF_LIST_ID name" in caplog.text


def test_seg_quotes_everything():
    assert seg("DX trusted client IPs") == "DX%20trusted%20client%20IPs"
    assert seg("a/b?c#d") == "a%2Fb%3Fc%23d"


def test_path_segments_quoted(mock):
    b = ZeroTrustList(mock.base, TOKEN, "acc ount/../x", ZT_LIST, timeout=5)
    with pytest.raises(CloudflareError) as ei:  # 404 from the mock, not http.client.InvalidURL
        b.list_items()
    assert "HTTP 404" in str(ei.value)
    assert mock.s.raw_paths[-1].startswith("/client/v4/accounts/acc%20ount%2F..%2Fx/gateway/lists/" + ZT_LIST)


def test_invalid_url_becomes_cloudflare_error(mock):
    b = ZeroTrustList(mock.base + " bad", TOKEN, ACCOUNT, ZT_LIST, timeout=5)
    with pytest.raises(CloudflareError):
        b.list_items()


# ---- ntfy failure logging ----

def _send(mock, caplog, token=NTFY_TOKEN, url=None):
    caplog.set_level(logging.INFO, "cfip")
    n = Notifier(url or mock.ntfy_url, token, timeout=3)
    ok = n.send("t", "m", 5)
    return ok, caplog.text


@pytest.mark.parametrize("status", [401, 403])
def test_ntfy_auth_failure_logged(mock, caplog, status):
    mock.s.ntfy_status = status
    ok, text = _send(mock, caplog)
    assert not ok
    assert f"HTTP {status}" in text and "NTFY_TOKEN is likely invalid/expired or lacks write access" in text
    assert NTFY_TOKEN not in text


def test_ntfy_wrong_token_401(mock, caplog):
    ok, text = _send(mock, caplog, token="wrong-secret-xyz")
    assert not ok and "HTTP 401" in text and "NTFY_TOKEN" in text and "wrong-secret-xyz" not in text


def test_ntfy_500_logged(mock, caplog):
    mock.s.ntfy_status = 500
    ok, text = _send(mock, caplog)
    assert not ok and "HTTP 500" in text and "server error" in text and "NTFY_TOKEN is likely" not in text
    assert NTFY_TOKEN not in text


def test_ntfy_network_error_logged(caplog):
    caplog.set_level(logging.INFO, "cfip")
    n = Notifier("http://127.0.0.1:1/ntfy", NTFY_TOKEN, timeout=2)  # nothing listens on port 1
    assert not n.send("t", "m")
    assert "network error" in caplog.text and "URLError" in caplog.text and "refused" in caplog.text.lower()
    assert NTFY_TOKEN not in caplog.text


def test_ntfy_success_no_error(mock, caplog):
    ok, text = _send(mock, caplog)
    assert ok and "failed" not in text and mock.s.ntfy[-1]["priority"] == 5


def test_ntfy_scrub_masks_token():
    n = Notifier("http://x", "s3cr3t-tok")
    assert n._scrub("oops s3cr3t-tok leaked") == "oops *** leaked"


def test_ntfy_invalid_url_logged_not_raised(caplog):
    caplog.set_level(logging.INFO, "cfip")
    n = Notifier("http://127.0.0.1:1/bad topic", NTFY_TOKEN, timeout=2)
    assert not n.send("t", "m")
    assert "InvalidURL" in caplog.text and NTFY_TOKEN not in caplog.text
