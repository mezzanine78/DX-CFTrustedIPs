"""Configuration from environment variables. Secrets are held here but never logged."""
from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass, field

DEFAULT_NTFY_URL = "https://ntfy.ausict.com/bct-ryan-bl-4456629bd50c"
CODE_RE = re.compile(r"^[A-Z0-9][A-Z0-9_-]{1,31}$")


class ConfigError(ValueError):
    pass


def _bool(v: str | None, default: bool = False) -> bool:
    if v is None or v.strip() == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _int(env: dict, name: str, default: int, minimum: int = 0) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        val = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if val < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return val


def parse_static_allowlist(raw: str | None) -> dict[str, str]:
    """'Label=IP[/CIDR];Label2=IP' -> {canonical_network: label}. Commas, semicolons or newlines separate entries."""
    out: dict[str, str] = {}
    if not raw:
        return out
    for part in re.split(r"[;,\n]+", raw):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            label, value = (s.strip() for s in part.split("=", 1))
        else:
            label, value = "static", part
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ConfigError(f"STATIC_ALLOWLIST entry '{part}' is not a valid IP/CIDR") from exc
        if not re.fullmatch(r"[A-Za-z0-9 ._-]{1,64}", label):
            raise ConfigError(f"STATIC_ALLOWLIST label '{label}' has invalid characters")
        out[str(net)] = label
    return out


def parse_networks(raw: str | None) -> list:
    nets = []
    for part in re.split(r"[;,\s]+", raw or ""):
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError as exc:
                raise ConfigError(f"'{part}' is not a valid IP/CIDR") from exc
    return nets


@dataclass
class Config:
    cf_api_token: str = field(default="", repr=False)
    cf_account_id: str = ""
    cf_list_id: str = ""
    cf_list_kind: str = "zerotrust"  # zerotrust (/gateway/lists) | rules (/rules/lists)
    cf_api_base: str = "https://api.cloudflare.com/client/v4"
    ntfy_url: str = DEFAULT_NTFY_URL
    ntfy_token: str = field(default="", repr=False)
    data_dir: str = "/data"
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    sync_interval: int = 3600
    sync_on_change: bool = True
    min_items: int = 2
    max_removals: int = 2
    stale_alert_hours: int = 13
    stale_ttl_hours: int = 168
    max_changes_per_day: int = 4
    ip_source: str = "request"  # request | client
    trusted_proxies: list = field(default_factory=list)
    static_allowlist: dict = field(default_factory=dict)
    managed_prefix: str = "dx-cfip"
    dry_run: bool = False
    http_timeout: int = 20
    bulk_poll_seconds: int = 120

    @classmethod
    def from_env(cls, env: dict | None = None) -> "Config":
        env = dict(os.environ if env is None else env)
        c = cls(
            cf_api_token=env.get("CF_API_TOKEN", "").strip(),
            cf_account_id=env.get("CF_ACCOUNT_ID", "").strip(),
            cf_list_id=env.get("CF_LIST_ID", "").strip(),
            cf_list_kind=env.get("CF_LIST_KIND", "zerotrust").strip().lower() or "zerotrust",
            cf_api_base=env.get("CF_API_BASE", "https://api.cloudflare.com/client/v4").rstrip("/"),
            ntfy_url=env.get("NTFY_URL", DEFAULT_NTFY_URL).strip(),
            ntfy_token=env.get("NTFY_TOKEN", "").strip(),
            data_dir=env.get("DATA_DIR", "/data"),
            listen_host=env.get("LISTEN_HOST", "0.0.0.0"),
            listen_port=_int(env, "LISTEN_PORT", 8080, 0),
            sync_interval=_int(env, "SYNC_INTERVAL_SECONDS", 3600, 60),
            sync_on_change=_bool(env.get("SYNC_ON_CHANGE"), True),
            min_items=_int(env, "MIN_ITEMS", 2, 0),
            max_removals=_int(env, "MAX_REMOVALS_PER_RUN", 2, 0),
            stale_alert_hours=_int(env, "STALE_ALERT_HOURS", 13, 1),
            stale_ttl_hours=_int(env, "STALE_TTL_HOURS", 168, 1),
            max_changes_per_day=_int(env, "MAX_IP_CHANGES_PER_DAY", 4, 1),
            ip_source=env.get("IP_SOURCE", "request").strip().lower() or "request",
            trusted_proxies=parse_networks(env.get("TRUSTED_PROXIES", "10.23.23.176")),
            static_allowlist=parse_static_allowlist(env.get("STATIC_ALLOWLIST")),
            managed_prefix=env.get("MANAGED_PREFIX", "dx-cfip").strip() or "dx-cfip",
            dry_run=_bool(env.get("DRY_RUN"), False),
            http_timeout=_int(env, "HTTP_TIMEOUT_SECONDS", 20, 1),
            bulk_poll_seconds=_int(env, "BULK_POLL_SECONDS", 120, 1),
        )
        if c.cf_list_kind not in ("zerotrust", "rules"):
            raise ConfigError("CF_LIST_KIND must be 'zerotrust' or 'rules'")
        if c.ip_source not in ("request", "client"):
            raise ConfigError("IP_SOURCE must be 'request' or 'client'")
        if not re.fullmatch(r"[a-z0-9-]{2,20}", c.managed_prefix):
            raise ConfigError("MANAGED_PREFIX must be 2-20 chars of a-z, 0-9 or '-'")
        if c.stale_ttl_hours <= c.stale_alert_hours:
            raise ConfigError("STALE_TTL_HOURS must be greater than STALE_ALERT_HOURS")
        return c

    def require_cloudflare(self) -> None:
        missing = [n for n, v in (("CF_API_TOKEN", self.cf_api_token), ("CF_ACCOUNT_ID", self.cf_account_id),
                                  ("CF_LIST_ID", self.cf_list_id)) if not v]
        if missing:
            raise ConfigError("missing required env: " + ", ".join(missing))
