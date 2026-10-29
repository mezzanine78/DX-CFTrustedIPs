from cfip.__main__ import main


def run(monkeypatch, env, argv, capsys):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    code = main(argv)
    return code, capsys.readouterr()


def test_cli_dry_run_prints_diff(ctx_factory, monkeypatch, capsys):
    c = ctx_factory()
    c.set_client_ip("ACME", "198.51.100.7", "Acme")
    code, out = run(monkeypatch, c.env, ["sync", "--dry-run"], capsys)
    assert code == 0
    assert "DRY-RUN diff:" in out.out and "+ 198.51.100.7  dx-cfip:ACME Acme" in out.out
    assert c.items() == {} and c.mock.s.ntfy == []


def test_cli_guard_exit_3(ctx_factory, monkeypatch, capsys):
    c = ctx_factory(MAX_REMOVALS_PER_RUN=0)
    c.set_client_ip("ACME", "198.51.100.7")
    c.syncer.run()
    c.store.remove_client("ACME")
    code, out = run(monkeypatch, c.env, ["sync"], capsys)
    assert code == 3 and "GUARD: mass-removal" in out.out


def test_cli_config_error_exit_2(monkeypatch, capsys, tmp_path):
    code, out = run(monkeypatch, {"CF_LIST_KIND": "nope", "DATA_DIR": str(tmp_path)}, ["sync"], capsys)
    assert code == 2


def test_cli_missing_cf_env_exit_2(monkeypatch, capsys, tmp_path):
    for k in ("CF_API_TOKEN", "CF_ACCOUNT_ID", "CF_LIST_ID"):
        monkeypatch.delenv(k, raising=False)
    code, out = run(monkeypatch, {"DATA_DIR": str(tmp_path)}, ["sync"], capsys)
    assert code == 2 and "CF_API_TOKEN" in out.err


def test_cli_client_lifecycle(monkeypatch, capsys, tmp_path):
    env = {"DATA_DIR": str(tmp_path)}
    code, out = run(monkeypatch, env, ["client", "add", "acme", "Acme Pty", "--cidr", "9.9.9.0/24"], capsys)
    assert code == 0 and "token" in out.out
    token = out.out.strip().splitlines()[-1]
    assert token not in open(tmp_path / "clients.json").read()  # only the hash is stored
    code, out = run(monkeypatch, env, ["client", "list"], capsys)
    assert "ACME" in out.out and "9.9.9.0/24" in out.out
    code, out = run(monkeypatch, env, ["client", "rotate", "ACME"], capsys)
    assert out.out.strip().splitlines()[-1] != token
    assert run(monkeypatch, env, ["client", "add", "ACME", "x"], capsys)[0] == 1
    assert run(monkeypatch, env, ["client", "add", "bad code!", "x"], capsys)[0] == 1
    assert run(monkeypatch, env, ["client", "disable", "ACME"], capsys)[0] == 0
    assert run(monkeypatch, env, ["status"], capsys)[0] == 0
    assert run(monkeypatch, env, ["client", "remove", "ACME"], capsys)[0] == 0
