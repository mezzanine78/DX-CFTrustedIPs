import pytest

from cfip.config import Config, ConfigError, parse_static_allowlist
from cfip.util import canonical, is_public_ipv4, item_value


def test_static_allowlist_parsing():
    out = parse_static_allowlist("BCT-Office=203.0.113.10; BCT DR=203.0.113.64/29,198.51.100.1")
    assert out == {"203.0.113.10/32": "BCT-Office", "203.0.113.64/29": "BCT DR", "198.51.100.1/32": "static"}
    with pytest.raises(ConfigError):
        parse_static_allowlist("x=not-an-ip")


@pytest.mark.parametrize("ip,ok", [("8.8.8.8", True), ("203.0.113.5", False), ("10.1.2.3", False),
                                   ("192.168.1.1", False), ("100.64.1.1", False), ("127.0.0.1", False),
                                   ("169.254.1.1", False), ("224.0.0.1", False), ("1.2.3.4/32", False),
                                   ("01.2.3.4", False), ("2001:db8::1", False), ("", False), (None, False),
                                   ("1.1.1.1", True), ("256.1.1.1", False)])
def test_public_ipv4(ip, ok):
    assert is_public_ipv4(ip) is ok


def test_canonical_and_value():
    assert canonical("1.2.3.4") == canonical("1.2.3.4/32") == "1.2.3.4/32"
    assert item_value("1.2.3.4/32") == "1.2.3.4" and item_value("1.2.3.0/24") == "1.2.3.0/24"


def test_bad_config_values():
    with pytest.raises(ConfigError):
        Config.from_env({"CF_LIST_KIND": "waf"})
    with pytest.raises(ConfigError):
        Config.from_env({"STALE_TTL_HOURS": "5", "STALE_ALERT_HOURS": "10"})
    with pytest.raises(ConfigError):
        Config.from_env({"MAX_REMOVALS_PER_RUN": "abc"})
    with pytest.raises(ConfigError):
        Config.from_env({}).require_cloudflare()
