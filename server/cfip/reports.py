"""Handle collector reports: authenticate, determine the site's public IP, record it."""
from __future__ import annotations

import ipaddress
import logging

from .util import is_public_ipv4, now

log = logging.getLogger("cfip.reports")
DAY = 86400


def observed_ip(cfg, peer: str, xff: str | None) -> str:
    """Source IP of the request. X-Forwarded-For is honoured only when the TCP peer is a
    trusted proxy (NPM). We take the right-most XFF hop that is not itself a trusted proxy,
    i.e. the address NPM actually saw, so a client cannot spoof it by sending its own XFF."""
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return peer
    if not xff or not any(peer_ip in n for n in cfg.trusted_proxies):
        return peer
    for hop in reversed([h.strip() for h in xff.split(",") if h.strip()]):
        try:
            hip = ipaddress.ip_address(hop)
        except ValueError:
            return peer  # malformed header: fall back to the peer address
        if not any(hip in n for n in cfg.trusted_proxies):
            return str(hip)
    return peer


def handle_report(cfg, store, notifier, body: dict, token: str, peer: str, xff: str | None):
    """Returns (http_status, response_dict, changed: bool)."""
    code = str(body.get("client") or "").strip().upper()
    rec = store.verify(code, token)
    if rec is None:
        return 401, {"ok": False, "error": "unauthorized"}, False

    seen = observed_ip(cfg, peer, xff)
    reported = str(body.get("ip") or "").strip() or None
    obs_ok, rep_ok = is_public_ipv4(seen), is_public_ipv4(reported)
    if cfg.ip_source == "request":
        chosen = seen if obs_ok else (reported if rep_ok else None)
    else:
        chosen = reported if rep_ok else (seen if obs_ok else None)
    if not chosen:
        return 422, {"ok": False, "error": "no public IPv4 (observed or reported)", "observed_ip": seen}, False

    allowed = rec.get("allowed_cidrs") or []
    if allowed and not any(ipaddress.ip_address(chosen) in ipaddress.ip_network(c, strict=False) for c in allowed):
        notifier.send(f"{code} reported IP outside allowed range",
                      f"{code} ({rec.get('name')}) reported {chosen}, not in {', '.join(allowed)}. Rejected.", 5)
        return 403, {"ok": False, "error": "ip not allowed for this client"}, False

    t = now()
    changed = False
    with store.lock:
        st = store.state()
        cst = st["clients"].setdefault(code, {"first_seen": t, "changes": []})
        mismatch = bool(obs_ok and rep_ok and seen != reported)
        if mismatch and st["alerts"].get(f"mismatch:{code}") != f"{seen}|{reported}":
            notifier.send(f"{code} IP mismatch",
                          f"{code} ({rec.get('name')}): request came from {seen} but the client reported {reported}. "
                          f"Using {chosen} (IP_SOURCE={cfg.ip_source}). Multi-WAN or a proxy at the site?", 4)
            st["alerts"][f"mismatch:{code}"] = f"{seen}|{reported}"
        cst.update({"last_seen": t, "observed_ip": seen, "reported_ip": reported,
                    "hostname": str(body.get("hostname") or "")[:64], "agent": str(body.get("version") or "")[:16]})
        cst["changes"] = [c for c in cst.get("changes", []) if t - c < DAY]
        status = "unchanged"
        if cst.get("ip") != chosen:
            if cst.get("ip") and len(cst["changes"]) >= cfg.max_changes_per_day:
                if cst.get("pending_ip") != chosen:
                    notifier.send(f"{code} IP change QUARANTINED",
                                  f"{code} ({rec.get('name')}) changed IP {len(cst['changes'])} times in 24h. "
                                  f"New IP {chosen} is NOT trusted yet; {cst['ip']} stays.\n"
                                  f"Approve: python -m cfip client approve {code}", 5)
                cst["pending_ip"] = chosen
                status = "quarantined"
            else:
                cst["previous_ip"] = cst.get("ip")
                cst["ip"] = chosen
                cst["last_change"] = t
                if cst.get("previous_ip"):  # first sighting is not a "change"
                    cst["changes"].append(t)
                cst.pop("pending_ip", None)
                changed = True
                status = "changed" if cst.get("previous_ip") else "new"
        elif cst.get("pending_ip"):
            cst.pop("pending_ip", None)  # flapped back to the trusted IP
        store.save_state(st)
    log.info("report %s status=%s", code, status)
    return 200, {"ok": True, "client": code, "ip": chosen, "observed_ip": seen, "status": status}, changed
