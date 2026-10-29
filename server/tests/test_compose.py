import os

import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_compose_valid_and_latest_tags():
    with open(os.path.join(ROOT, "docker-compose.yml")) as fh:
        doc = yaml.safe_load(fh)
    svc = doc["services"]["cfip"]
    assert svc["image"].endswith(":latest")
    assert svc["build"] == "./server" and os.path.isfile(os.path.join(ROOT, "server", "Dockerfile"))
    assert svc["env_file"] == ".env"
    assert any(v.endswith(":/data") for v in svc["volumes"])
    assert "cfip-data" in doc["volumes"]
    with open(os.path.join(ROOT, "server", "Dockerfile")) as fh:
        froms = [line.split()[1] for line in fh if line.startswith("FROM ")]
    assert froms and all(f.endswith(":latest") for f in froms)


def test_env_example_has_no_values_for_secrets():
    with open(os.path.join(ROOT, ".env.example")) as fh:
        env = dict(line.split("=", 1) for line in fh.read().splitlines() if line and not line.startswith("#"))
    for key in ("CF_API_TOKEN", "NTFY_TOKEN", "CF_ACCOUNT_ID", "CF_LIST_ID"):
        assert env[key].split("#")[0].strip() == ""


def test_gitignore_excludes_env():
    with open(os.path.join(ROOT, ".gitignore")) as fh:
        lines = fh.read().splitlines()
    assert ".env" in lines and "!.env.example" in lines
