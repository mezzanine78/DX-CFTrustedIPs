"""Desired-state computation, diff and guarded sync against the Cloudflare list."""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field

from .cloudflare import CloudflareError, Item
from .store import StoreError
from .util import canonical, iso, item_value, now

log = logging.getLogger("cfip.sync")
GUARD_REALERT_SECONDS = 12 * 3600


@dataclass
class Plan:
    desired: dict = field(default_factory=dict)       # net -> description
    adds: list = field(default_factory=list)          # [(net, description)]
    removes: list = field(default_factory=list)       # [Item]
    blocked_removes: list = field(default_factory=list)
    unmanaged_overlap: list = field(default_factory=list)  # desired nets already present unmanaged
    drift: list = field(default_factory=list)         # managed nets whose description changed
    guards: list = field(default_factory=list)        # human-readable guard trips
    stale: list = field(default_factory=list)         # (code, last_seen) past STALE_ALERT_HOURS
    expired: list = field(default_factory=list)       # codes past STALE_TTL_HOURS
    quarantined: list = field(default_factory=list)   # codes with an IP change awaiting approval

    def diff_text(self) -> str:
        lines = [f"+ {item_value(n)}  {d}" for n, d in self.adds]
        lines += [f"- {i.value}  {i.description}" for i in self.removes]
        lines += [f"! {i.value}  {i.description}  (removal BLOCKED by guard)" for i in self.blocked_removes]
        lines += [f"= {item_value(n)}  already in list as an unmanaged item (left alone)" for n in self.unmanaged_overlap]
        lines += [f"~ {item_value(n)}  description differs (not rewritten)" for n in self.drift]
        return "\n".join(lines) if lines else "(no changes)"


@dataclass
class Result:
    ok: bool
    plan: Plan | None = None
    applied: bool = False
    dry_run: bool = False
    error: str = ""


def describe(prefix: str, codes: list[str], names: list[str]) -> str:
    text = f"{prefix}:{','.join(codes)} {'; '.join(names)}".strip()
    return text[:200]


def owned(prefix: str, description: str) -> bool:
    return (description or "").startswith(prefix + ":")


def build_plan(cfg, clients: dict, state: dict, current: list[Item], allow_removals: int | None = None) -> Plan:
    plan = Plan()
    t = now()
    by_net: dict[str, list[tuple[str, str]]] = {}

    for net, label in cfg.static_allowlist.items():
        plan.desired[canonical(net)] = describe(cfg.managed_prefix, ["static"], [label])

    had_ip = 0
    for code in sorted(clients):
        rec = clients[code]
        cst = state.get("clients", {}).get(code) or {}
        ip = cst.get("ip")
        if rec.get("disabled") or not ip:
            continue
        had_ip += 1
        if cst.get("pending_ip"):
            plan.quarantined.append(code)
        age_h = (t - float(cst.get("last_seen") or 0)) / 3600.0
        if age_h > cfg.stale_ttl_hours:
            plan.expired.append(code)
            continue
        if age_h > cfg.stale_alert_hours:
            plan.stale.append((code, cst.get("last_seen")))
        by_net.setdefault(canonical(ip + "/32"), []).append((code, rec.get("name") or code))

    for net, owners in by_net.items():
        if net in plan.desired:  # already covered by the static allowlist
            continue
        plan.desired[net] = describe(cfg.managed_prefix, [c for c, _ in owners], [n for _, n in owners])

    managed = {i.net: i for i in current if owned(cfg.managed_prefix, i.description)}
    unmanaged = {i.net for i in current if not owned(cfg.managed_prefix, i.description)}

    for net, desc in sorted(plan.desired.items()):
        if net in managed:
            if managed[net].description != desc:
                plan.drift.append(net)
        elif net in unmanaged:
            plan.unmanaged_overlap.append(net)
        else:
            plan.adds.append((net, desc))
    removes = [i for n, i in sorted(managed.items()) if n not in plan.desired]

    # ---- guards: they only ever block removals; additions are always safe ----
    client_nets = len(by_net)
    if removes:
        if had_ip > 0 and client_nets == 0:
            plan.guards.append(f"empty-results: {had_ip} client(s) have IPs on record but none are current")
        if len(plan.desired) < cfg.min_items:
            plan.guards.append(f"min-count: desired list would have {len(plan.desired)} item(s) < MIN_ITEMS={cfg.min_items}")
        limit = cfg.max_removals if allow_removals is None else allow_removals
        if len(removes) > limit:
            plan.guards.append(f"mass-removal: {len(removes)} removals > limit {limit}")
    if plan.guards:
        plan.blocked_removes = removes
    else:
        plan.removes = removes
    return plan


class Syncer:
    def __init__(self, cfg, store, backend, notifier):
        self.cfg = cfg
        self.store = store
        self.backend = backend
        self.notifier = notifier
        self.lock = threading.Lock()

    def _alert_once(self, state: dict, key: str, title: str, msg: str, prio: int, every: int | None = None) -> None:
        last = state["alerts"].get(key)
        if last and (every is None or now() - last < every):
            return
        self.notifier.send(title, msg, prio)
        state["alerts"][key] = now()

    def run(self, dry_run: bool | None = None, allow_removals: int | None = None) -> Result:
        dry = self.cfg.dry_run if dry_run is None else dry_run
        with self.lock:
            try:
                clients = self.store.clients()
                state = self.store.state()
            except StoreError as exc:
                return self._fail(None, f"state unreadable, nothing changed: {exc}", dry)
            try:
                current = self.backend.list_items()
            except CloudflareError as exc:
                return self._fail(state, f"could not read Cloudflare list, nothing changed: {exc}", dry)

            plan = build_plan(self.cfg, clients, state, current, allow_removals)
            log.info("plan%s:\n%s", " (dry-run)" if dry else "", plan.diff_text())
            if dry:
                return Result(True, plan, dry_run=True)

            applied = False
            if plan.adds or plan.removes:
                try:
                    self.backend.apply([(item_value(n), d) for n, d in plan.adds], plan.removes)
                    applied = True
                except CloudflareError as exc:
                    return self._fail(state, f"Cloudflare update failed: {exc}\nPlanned:\n{plan.diff_text()}", dry, plan)
                self.notifier.send(
                    f"list updated (+{len(plan.adds)} -{len(plan.removes)})",
                    plan.diff_text() + (f"\nExpired (no report for >{self.cfg.stale_ttl_hours}h): "
                                        + ", ".join(plan.expired) if plan.expired else ""), 3, "globe_with_meridians")

            if plan.guards:
                sig = "guard:" + "|".join(sorted(i.net for i in plan.blocked_removes))
                self._alert_once(state, sig, "guard tripped - removals blocked",
                                 "\n".join(plan.guards) + "\n" + plan.diff_text()
                                 + "\nRe-run with: python -m cfip sync --allow-removals N", 5, GUARD_REALERT_SECONDS)
            live = {c for c, _ in plan.stale}
            for code, seen in plan.stale:
                self._alert_once(state, f"stale:{code}", f"{code} has not reported",
                                 f"{code} last reported {iso(seen)}. Its IP stays in the list until "
                                 f"STALE_TTL_HOURS={self.cfg.stale_ttl_hours}h passes.", 4)
            for key in [k for k in state["alerts"] if k.startswith("stale:") and k[6:] not in live]:
                del state["alerts"][key]  # re-arm once the client reports again
            if not plan.guards:  # re-arm guard alerts once the condition clears
                for key in [k for k in state["alerts"] if k.startswith("guard:")]:
                    del state["alerts"][key]
            state["last_sync"] = {"at": now(), "ok": True, "adds": len(plan.adds), "removes": len(plan.removes),
                                  "blocked": len(plan.blocked_removes), "desired": len(plan.desired)}
            state["alerts"].pop("sync-error", None)
            self.store.save_state(state)
            return Result(True, plan, applied=applied)

    def _fail(self, state, msg: str, dry: bool, plan: Plan | None = None) -> Result:
        log.error(msg)
        if not dry:
            self.notifier.send("sync FAILED", msg, 5, "rotating_light")
            if state is not None:
                state["last_sync"] = {"at": now(), "ok": False, "error": msg[:300]}
                state["alerts"]["sync-error"] = now()
                try:
                    self.store.save_state(state)
                except (OSError, StoreError):
                    log.exception("could not save state")
        return Result(False, plan, dry_run=dry, error=msg)
