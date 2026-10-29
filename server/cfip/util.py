"""Small shared helpers."""
from __future__ import annotations

import ipaddress
import time
from datetime import datetime, timezone


def now() -> float:
    return time.time()


def iso(ts: float | None) -> str:
    if not ts:
        return "never"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_public_ipv4(value: str | None) -> bool:
    """True for a syntactically valid, globally routable IPv4 address (no CIDR)."""
    if not value or not isinstance(value, str) or "/" in value:
        return False
    try:
        ip = ipaddress.IPv4Address(value.strip())
    except ValueError:
        return False
    if str(ip) != value.strip():  # reject leading zeros etc.
        return False
    return ip.is_global and not ip.is_multicast


def canonical(value: str) -> str:
    """Normalise an IP or CIDR so '1.2.3.4' and '1.2.3.4/32' compare equal."""
    return str(ipaddress.ip_network(value.strip(), strict=False))


def item_value(net: str) -> str:
    """Value to send to Cloudflare: bare IP for host routes, CIDR otherwise."""
    n = ipaddress.ip_network(net, strict=False)
    if n.prefixlen == n.max_prefixlen:
        return str(n.network_address)
    return str(n)
