import pytest

KINDS = ["zerotrust", "rules"]


def seed(ctx, entries):
    """entries: {value: description}"""
    import secrets
    for v, d in entries.items():
        if ctx.cfg.cf_list_kind == "zerotrust":
            ctx.mock.s.zt_items.append({"value": v, "description": d})
        else:
            ctx.mock.s.rules_items.append({"id": secrets.token_hex(16), "ip": v, "comment": d})


@pytest.mark.parametrize("kind", KINDS)
def test_initial_sync_adds_static_and_clients_with_tags(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7", "Acme Pty Ltd")
    c.set_client_ip("BETA", "198.51.100.8", "Beta Ltd")
    r = c.syncer.run()
    assert r.ok and r.applied
    items = c.items()
    assert items["203.0.113.10"] == "dx-cfip:static BCT-Office"
    assert items["198.51.100.7"] == "dx-cfip:ACME Acme Pty Ltd"
    assert items["198.51.100.8"] == "dx-cfip:BETA Beta Ltd"
    assert [n["priority"] for n in c.mock.s.ntfy] == [3]
    assert "+ 198.51.100.7" in c.mock.s.ntfy[0]["body"]


@pytest.mark.parametrize("kind", KINDS)
def test_idempotent_second_run_no_writes_no_alert(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7")
    c.set_client_ip("BETA", "198.51.100.8")
    c.syncer.run()
    before = len([r for r in c.mock.s.requests if r[0] != "GET"])
    n = len(c.mock.s.ntfy)
    r = c.syncer.run()
    assert r.ok and not r.applied
    assert not r.plan.adds and not r.plan.removes
    assert len([r for r in c.mock.s.requests if r[0] != "GET"]) == before
    assert len(c.mock.s.ntfy) == n


@pytest.mark.parametrize("kind", KINDS)
def test_ip_change_replaces_item_and_alerts(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7")
    c.set_client_ip("BETA", "198.51.100.8")
    c.syncer.run()
    c.set_client_ip("ACME", "192.0.2.55")
    r = c.syncer.run()
    assert r.ok and r.applied
    items = c.items()
    assert "198.51.100.7" not in items and items["192.0.2.55"].startswith("dx-cfip:ACME")
    body = c.mock.s.ntfy[-1]["body"]
    assert "+ 192.0.2.55" in body and "- 198.51.100.7" in body
    assert c.mock.s.ntfy[-1]["priority"] == 3


@pytest.mark.parametrize("kind", KINDS)
def test_unmanaged_items_left_alone(ctx_factory, kind):
    c = ctx_factory(kind)
    seed(c, {"192.0.2.200": "Ryan home - manual", "192.0.2.201": ""})
    c.set_client_ip("ACME", "198.51.100.7")
    c.set_client_ip("BETA", "192.0.2.200")  # same IP as a manual entry -> not duplicated
    r = c.syncer.run()
    assert r.ok
    items = c.items()
    assert items["192.0.2.200"] == "Ryan home - manual"
    assert items["192.0.2.201"] == ""
    assert "192.0.2.200/32" in r.plan.unmanaged_overlap
    assert not r.plan.removes


@pytest.mark.parametrize("kind", KINDS)
def test_static_allowlist_always_included_even_without_clients(ctx_factory, kind):
    c = ctx_factory(kind, STATIC_ALLOWLIST="BCT-Office=203.0.113.10;BCT-DR=203.0.113.64/29")
    r = c.syncer.run()
    assert r.ok
    items = c.items()
    assert "203.0.113.10" in items and "203.0.113.64/29" in items


@pytest.mark.parametrize("kind", KINDS)
def test_dry_run_prints_diff_and_writes_nothing(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7")
    r = c.syncer.run(dry_run=True)
    assert r.ok and r.dry_run and not r.applied
    assert "+ 198.51.100.7" in r.plan.diff_text()
    assert c.items() == {}
    assert not [x for x in c.mock.s.requests if x[0] != "GET"]
    assert c.mock.s.ntfy == []


@pytest.mark.parametrize("kind", KINDS)
def test_empty_results_guard_blocks_wipe(ctx_factory, kind):
    c = ctx_factory(kind, STALE_TTL_HOURS=24, STALE_ALERT_HOURS=12, MIN_ITEMS=0, MAX_REMOVALS_PER_RUN=10)
    c.set_client_ip("ACME", "198.51.100.7")
    c.set_client_ip("BETA", "198.51.100.8")
    c.syncer.run()
    # every client now past TTL -> looks like "nobody reported": must not wipe
    c.set_client_ip("ACME", "198.51.100.7", age_hours=48)
    c.set_client_ip("BETA", "198.51.100.8", age_hours=48)
    r = c.syncer.run()
    assert r.ok
    assert any(g.startswith("empty-results") for g in r.plan.guards)
    assert not r.plan.removes and len(r.plan.blocked_removes) == 2
    assert "198.51.100.7" in c.items() and "198.51.100.8" in c.items()
    assert c.mock.s.ntfy[-1]["priority"] == 5


@pytest.mark.parametrize("kind", KINDS)
def test_min_count_guard(ctx_factory, kind):
    c = ctx_factory(kind, MIN_ITEMS=3, STATIC_ALLOWLIST="")
    c.set_client_ip("ACME", "198.51.100.7")
    c.set_client_ip("BETA", "198.51.100.8")
    c.set_client_ip("GAMA", "198.51.100.9")
    c.syncer.run()
    c.store.set_client("GAMA", disabled=True)
    r = c.syncer.run()
    assert any(g.startswith("min-count") for g in r.plan.guards)
    assert "198.51.100.9" in c.items()


@pytest.mark.parametrize("kind", KINDS)
def test_mass_removal_guard_and_override(ctx_factory, kind):
    c = ctx_factory(kind, MAX_REMOVALS_PER_RUN=2, MIN_ITEMS=1)
    for i, code in enumerate(["AAA", "BBB", "CCC", "DDD"]):
        c.set_client_ip(code, f"198.51.100.{10 + i}")
    c.syncer.run()
    for code in ["AAA", "BBB", "CCC"]:
        c.store.remove_client(code)
    c.set_client_ip("EEE", "198.51.100.50")
    r = c.syncer.run()
    assert any(g.startswith("mass-removal") for g in r.plan.guards)
    items = c.items()
    assert "198.51.100.50" in items  # additions still applied
    assert all(f"198.51.100.{10 + i}" in items for i in range(3))
    assert c.mock.s.ntfy[-1]["priority"] == 5
    # guard alert is not repeated every run
    n = len(c.mock.s.ntfy)
    c.syncer.run()
    assert len(c.mock.s.ntfy) == n
    # explicit operator override
    r = c.syncer.run(allow_removals=3)
    assert r.ok and len(r.plan.removes) == 3 and not r.plan.guards
    assert not any(f"198.51.100.{10 + i}" in c.items() for i in range(3))


@pytest.mark.parametrize("kind", KINDS)
def test_partial_or_failed_read_aborts_without_writes(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7")
    c.mock.s.fail_get = True
    r = c.syncer.run()
    assert not r.ok and "nothing changed" in r.error
    writes = [x for x in c.mock.s.requests if x[0] in ("PATCH", "DELETE") or (x[0] == "POST" and x[1] != "/ntfy")]
    assert not writes
    assert c.mock.s.ntfy[-1]["priority"] == 5


def test_zerotrust_partial_page_count_detected(ctx_factory):
    c = ctx_factory("zerotrust")
    seed(c, {"192.0.2.1": "dx-cfip:static X"})
    c.mock.s.lie_total = True
    r = c.syncer.run()
    assert not r.ok and "partial read" in r.error
    assert c.mock.s.ntfy[-1]["priority"] == 5


@pytest.mark.parametrize("kind", KINDS)
def test_pagination(ctx_factory, kind):
    c = ctx_factory(kind)
    c.mock.s.per_page_cap = 3
    seed(c, {f"192.0.2.{i}": "manual" for i in range(1, 11)})
    items = c.syncer.backend.list_items()
    assert len(items) == 10


@pytest.mark.parametrize("kind", KINDS)
def test_write_failure_alerts_p5(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7")
    c.mock.s.fail_write = True
    r = c.syncer.run()
    assert not r.ok and "update failed" in r.error
    assert c.mock.s.ntfy[-1]["priority"] == 5


@pytest.mark.parametrize("kind", KINDS)
def test_stale_client_kept_and_alerted_once_then_expires(ctx_factory, kind):
    c = ctx_factory(kind, STALE_ALERT_HOURS=13, STALE_TTL_HOURS=72, MIN_ITEMS=1)
    c.set_client_ip("ACME", "198.51.100.7")
    c.set_client_ip("BETA", "198.51.100.8")
    c.syncer.run()
    c.set_client_ip("ACME", "198.51.100.7", age_hours=20)
    r = c.syncer.run()
    assert "198.51.100.7" in c.items()
    assert [s[0] for s in r.plan.stale] == ["ACME"]
    stale_alerts = [n for n in c.mock.s.ntfy if "has not reported" in n["title"]]
    assert len(stale_alerts) == 1 and stale_alerts[0]["priority"] == 4
    c.syncer.run()
    assert len([n for n in c.mock.s.ntfy if "has not reported" in n["title"]]) == 1
    c.set_client_ip("ACME", "198.51.100.7", age_hours=80)
    r = c.syncer.run()
    assert r.plan.expired == ["ACME"] and "198.51.100.7" not in c.items()


@pytest.mark.parametrize("kind", KINDS)
def test_shared_ip_merged_into_one_item(ctx_factory, kind):
    c = ctx_factory(kind)
    c.set_client_ip("ACME", "198.51.100.7", "Acme")
    c.set_client_ip("BETA", "198.51.100.7", "Beta")
    c.syncer.run()
    assert c.items()["198.51.100.7"] == "dx-cfip:ACME,BETA Acme; Beta"


def test_corrupt_state_aborts(ctx_factory):
    c = ctx_factory()
    c.set_client_ip("ACME", "198.51.100.7")
    c.syncer.run()
    with open(c.store.state_path, "w") as fh:
        fh.write("{not json")
    r = c.syncer.run()
    assert not r.ok and "state unreadable" in r.error
    assert "198.51.100.7" in c.items()


def test_ntfy_token_never_in_logs_or_messages(ctx_factory, caplog):
    from mockcf import NTFY_TOKEN, TOKEN
    c = ctx_factory()
    c.set_client_ip("ACME", "198.51.100.7")
    c.mock.s.fail_write = True
    with caplog.at_level("DEBUG"):
        c.syncer.run()
    blob = caplog.text + "".join(n["body"] + (n["title"] or "") for n in c.mock.s.ntfy)
    assert NTFY_TOKEN not in blob and TOKEN not in blob
    assert TOKEN not in repr(c.cfg) and NTFY_TOKEN not in repr(c.cfg)
