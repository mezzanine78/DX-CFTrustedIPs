"""CLI entry point:  python -m cfip <command>

  serve                              run report endpoint + hourly sync (container default)
  sync [--dry-run] [--allow-removals N]
  status                             clients, last report, current IP, last sync
  client add CODE "Name" [--cidr X]  prints the new token ONCE
  client rotate CODE                 prints the new token ONCE
  client list | disable CODE | enable CODE | remove CODE | approve CODE | cidrs CODE [CIDR ...]

Exit codes: 0 ok, 1 sync failed / error, 2 config error, 3 guard tripped (removals blocked).
"""
from __future__ import annotations

import argparse
import ipaddress
import logging
import signal
import sys
import threading

from .cloudflare import CloudflareError, ListLookupError, make_backend
from .config import Config, ConfigError
from .notify import Notifier
from .store import Store, StoreError
from .sync import Syncer
from .util import iso, now


def _build(cfg, need_cf=True):
    if need_cf:
        cfg.require_cloudflare()
    store = Store(cfg.data_dir)
    notifier = Notifier(cfg.ntfy_url, cfg.ntfy_token, enabled=not cfg.dry_run)
    syncer = None
    if need_cf:
        backend = make_backend(cfg)
        try:  # validate CF_LIST_ID at startup: an ID passes through, a list name is resolved once
            backend.resolve_list_id()
        except ListLookupError:
            raise  # a ConfigError: exit 2 with the explanation
        except CloudflareError as exc:  # API unreachable right now: retried at the first sync
            logging.getLogger("cfip").warning("could not resolve CF_LIST_ID yet (%s); will retry at sync", exc)
        syncer = Syncer(cfg, store, backend, notifier)
    return store, notifier, syncer


def cmd_serve(cfg):
    from .server import App, serve
    store, notifier, syncer = _build(cfg)
    app = App(cfg, store, notifier, syncer)
    httpd = serve(app)
    def _stop(*_):  # shutdown() blocks until serve_forever returns, so call it off the main thread
        app.stop.set()
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _stop)
    logging.getLogger("cfip").info("listening on %s:%s (list=%s, dry_run=%s)", cfg.listen_host,
                                   cfg.listen_port, cfg.cf_list_kind, cfg.dry_run)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def cmd_sync(cfg, args):
    _, _, syncer = _build(cfg)
    res = syncer.run(dry_run=args.dry_run or None, allow_removals=args.allow_removals)
    if res.plan is not None:
        print(("DRY-RUN " if res.dry_run else "") + "diff:")
        print(res.plan.diff_text())
        for g in res.plan.guards:
            print("GUARD: " + g)
    if not res.ok:
        print("ERROR: " + res.error, file=sys.stderr)
        return 1
    return 3 if res.plan and res.plan.guards else 0


def cmd_status(cfg):
    store = Store(cfg.data_dir)
    clients, st = store.clients(), store.state()
    print(f"{'CODE':<12} {'NAME':<28} {'IP':<16} {'LAST SEEN (UTC)':<21} FLAGS")
    for code in sorted(clients):
        c, s = clients[code], st["clients"].get(code, {})
        age_h = (now() - float(s.get("last_seen") or 0)) / 3600
        flags = [f for f, on in (("disabled", c.get("disabled")), ("pending:" + str(s.get("pending_ip")), s.get("pending_ip")),
                                 ("stale", s.get("last_seen") and age_h > cfg.stale_alert_hours)) if on]
        print(f"{code:<12} {c.get('name', '')[:28]:<28} {s.get('ip') or '-':<16} {iso(s.get('last_seen')):<21} {' '.join(flags)}")
    print("last sync:", st.get("last_sync") or "never")
    return 0


def cmd_client(cfg, args):
    store = Store(cfg.data_dir)
    a = args.action
    if a == "list":
        for code, c in sorted(store.clients().items()):
            flag = "(disabled)" if c.get("disabled") else ""
            print(f"{code:<12} {c.get('name', '')} {flag} {','.join(c.get('allowed_cidrs') or [])}")
        return 0
    if not args.code:
        raise StoreError("client code required")
    code = args.code.upper()
    if a in ("add", "rotate"):
        cidrs = [str(ipaddress.ip_network(x, strict=False)) for x in (args.cidr or [])]
        token = store.add_client(code, args.name or code, cidrs) if a == "add" else store.rotate_client(code)
        # Shown once, to the operator's terminal only, so it can be put in N-central. Never logged.
        print(f"Client {code} token (store it in N-central now, it is not shown again):\n{token}")
    elif a in ("disable", "enable"):
        store.set_client(code, disabled=(a == "disable"))
        print(f"{code} {a}d (takes effect at next sync)")
    elif a == "remove":
        store.remove_client(code)
        print(f"{code} removed (its IP is removed at next sync, subject to guards)")
    elif a == "cidrs":
        store.set_client(code, allowed_cidrs=[str(ipaddress.ip_network(x, strict=False)) for x in args.rest])
        print(f"{code} allowed CIDRs: {', '.join(args.rest) or '(any)'}")
    elif a == "approve":
        with store.lock:
            st = store.state()
            cst = st["clients"].get(code) or {}
            if not cst.get("pending_ip"):
                raise StoreError(f"{code} has no pending IP")
            cst["previous_ip"], cst["ip"] = cst.get("ip"), cst.pop("pending_ip")
            cst["last_change"], cst["changes"] = now(), []
            store.save_state(st)
        print(f"{code} now trusted at {cst['ip']} (applied at next sync)")
    return 0


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s DX cfip %(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(prog="cfip", description="DX Cloudflare trusted-IP updater")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    s = sub.add_parser("sync")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--allow-removals", type=int, default=None, help="override MAX_REMOVALS_PER_RUN once")
    sub.add_parser("status")
    c = sub.add_parser("client")
    c.add_argument("action", choices=["add", "rotate", "list", "disable", "enable", "remove", "approve", "cidrs"])
    c.add_argument("code", nargs="?")
    c.add_argument("name", nargs="?")
    c.add_argument("rest", nargs="*")
    c.add_argument("--cidr", action="append")
    args = p.parse_args(argv)
    try:
        cfg = Config.from_env()
        if args.cmd == "serve":
            return cmd_serve(cfg)
        if args.cmd == "sync":
            return cmd_sync(cfg, args)
        if args.cmd == "status":
            return cmd_status(cfg)
        if args.action == "cidrs" and args.name:
            args.rest = [args.name] + args.rest
        return cmd_client(cfg, args)
    except ConfigError as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2
    except (StoreError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
