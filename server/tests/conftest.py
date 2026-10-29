import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mockcf import ACCOUNT, NTFY_TOKEN, RULES_LIST, TOKEN, ZT_LIST, MockServer  # noqa: E402

from cfip.cloudflare import make_backend  # noqa: E402
from cfip.config import Config  # noqa: E402
from cfip.notify import Notifier  # noqa: E402
from cfip.store import Store  # noqa: E402
from cfip.sync import Syncer  # noqa: E402


@pytest.fixture
def mock():
    m = MockServer()
    yield m
    m.close()


def make_env(mock, tmp_path, kind="zerotrust", **extra):
    env = {
        "CF_API_TOKEN": TOKEN, "CF_ACCOUNT_ID": ACCOUNT,
        "CF_LIST_ID": ZT_LIST if kind == "zerotrust" else RULES_LIST, "CF_LIST_KIND": kind,
        "CF_API_BASE": mock.base, "NTFY_URL": mock.ntfy_url, "NTFY_TOKEN": NTFY_TOKEN,
        "DATA_DIR": str(tmp_path / "data"), "STATIC_ALLOWLIST": "BCT-Office=203.0.113.10",
        "TRUSTED_PROXIES": "127.0.0.1", "MIN_ITEMS": "2", "MAX_REMOVALS_PER_RUN": "2",
        "LISTEN_HOST": "127.0.0.1", "LISTEN_PORT": "8080",
    }
    env.update({k: str(v) for k, v in extra.items()})
    return env


class Ctx:
    def __init__(self, mock, tmp_path, kind="zerotrust", **extra):
        self.mock = mock
        self.env = make_env(mock, tmp_path, kind, **extra)
        self.cfg = Config.from_env(self.env)
        self.store = Store(self.cfg.data_dir)
        self.notifier = Notifier(self.cfg.ntfy_url, self.cfg.ntfy_token)
        self.syncer = Syncer(self.cfg, self.store, make_backend(self.cfg), self.notifier)

    def items(self):
        s = self.mock.s
        if self.cfg.cf_list_kind == "zerotrust":
            return {i["value"]: i["description"] for i in s.zt_items}
        return {i["ip"]: i["comment"] for i in s.rules_items}

    def set_client_ip(self, code, ip, name=None, age_hours=0.0):
        import time
        if code not in self.store.clients():
            self.store.add_client(code, name or code)
        st = self.store.state()
        st["clients"].setdefault(code, {})
        st["clients"][code].update({"ip": ip, "last_seen": time.time() - age_hours * 3600, "changes": []})
        self.store.save_state(st)


@pytest.fixture
def ctx_factory(mock, tmp_path):
    def f(kind="zerotrust", **extra):
        return Ctx(mock, tmp_path, kind, **extra)
    return f
