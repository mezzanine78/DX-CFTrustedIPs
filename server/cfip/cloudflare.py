"""Cloudflare list backends.

zerotrust: Zero Trust (Cloudflare One) list - the kind Access policies reference with the
           'IP list' selector. GET /accounts/{a}/gateway/lists/{id}/items (paged),
           PATCH /accounts/{a}/gateway/lists/{id} {"append":[{value,description}], "remove":[value]}.
           Token permission: Account > Zero Trust > Edit ("Zero Trust Write").
rules:     Account-level custom IP list (WAF/Rules 'ip.src in $list').
           GET /accounts/{a}/rules/lists/{id}/items (cursor paged), POST/DELETE items (async bulk,
           poll /rules/lists/bulk_operations/{op}). Token permission: Account > Account Filter Lists > Edit.
"""
from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .util import canonical

log = logging.getLogger("cfip.cloudflare")


class CloudflareError(RuntimeError):
    pass


@dataclass
class Item:
    net: str           # canonical network, e.g. 203.0.113.5/32
    value: str         # value exactly as Cloudflare returned it (used for removal)
    description: str
    id: str | None = None


class _Http:
    def __init__(self, base: str, token: str, timeout: int):
        self.base = base.rstrip("/")
        self._token = token
        self.timeout = timeout

    def call(self, method: str, path: str, body=None, query: dict | None = None) -> dict:
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + self._token, "Content-Type": "application/json",
            "User-Agent": "dx-cfip/1.0"})
        for attempt in range(4):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    payload = json.loads(resp.read() or b"{}")
                break
            except urllib.error.HTTPError as exc:
                if exc.code == 429 and attempt < 3:  # pending bulk op / rate limit
                    time.sleep(min(2 ** attempt, 8))
                    continue
                detail = ""
                try:
                    errs = json.loads(exc.read() or b"{}").get("errors") or []
                    detail = "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs)[:300]
                except ValueError:
                    pass
                raise CloudflareError(f"{method} {path} -> HTTP {exc.code} {detail}".strip()) from None
            except (urllib.error.URLError, OSError) as exc:
                raise CloudflareError(f"{method} {path} -> {type(exc).__name__}: {getattr(exc, 'reason', exc)}") from None
        if not payload.get("success", False):
            errs = payload.get("errors") or []
            raise CloudflareError(f"{method} {path} -> success=false " +
                                  "; ".join(f"{e.get('code')}: {e.get('message')}" for e in errs)[:300])
        return payload


class ZeroTrustList:
    kind = "zerotrust"

    def __init__(self, base, token, account_id, list_id, timeout=20, **_):
        self.http = _Http(base, token, timeout)
        self.path = f"/accounts/{account_id}/gateway/lists/{list_id}"

    def list_items(self) -> list[Item]:
        items: list[Item] = []
        page, total_pages, total_count = 1, 1, None
        while page <= total_pages:
            p = self.http.call("GET", self.path + "/items", query={"page": page, "per_page": 1000})
            res = p.get("result") or []
            info = p.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if info.get("total_count") is not None:
                total_count = int(info["total_count"])
            for r in res:
                v = r.get("value", "")
                try:
                    items.append(Item(canonical(v), v, r.get("description") or ""))
                except ValueError:
                    log.warning("ignoring non-IP list value")
            page += 1
            if page > 100:
                raise CloudflareError("too many pages")
        if total_count is not None and len(items) != total_count:
            raise CloudflareError(f"partial read: got {len(items)} of {total_count} items")
        return items

    def apply(self, adds: list[tuple[str, str]], removes: list[Item]) -> None:
        body = {}
        if adds:
            body["append"] = [{"value": v, "description": d} for v, d in adds]
        if removes:
            body["remove"] = [i.value for i in removes]
        if body:
            self.http.call("PATCH", self.path, body)


class RulesList:
    kind = "rules"

    def __init__(self, base, token, account_id, list_id, timeout=20, poll_seconds=120, **_):
        self.http = _Http(base, token, timeout)
        self.acct = f"/accounts/{account_id}/rules/lists"
        self.path = f"{self.acct}/{list_id}"
        self.poll_seconds = poll_seconds

    def list_items(self) -> list[Item]:
        items: list[Item] = []
        cursor = None
        for _ in range(200):
            q = {"per_page": 500}
            if cursor:
                q["cursor"] = cursor
            p = self.http.call("GET", self.path + "/items", query=q)
            for r in p.get("result") or []:
                if "ip" not in r:
                    continue
                items.append(Item(canonical(r["ip"]), r["ip"], r.get("comment") or "", r.get("id")))
            cursor = ((p.get("result_info") or {}).get("cursors") or {}).get("after")
            if not cursor:
                return items
        raise CloudflareError("too many pages")

    def _wait(self, op_id: str) -> None:
        deadline = time.monotonic() + self.poll_seconds
        while True:
            p = self.http.call("GET", f"{self.acct}/bulk_operations/{op_id}")
            st = (p.get("result") or {}).get("status")
            if st == "completed":
                return
            if st == "failed":
                raise CloudflareError(f"bulk operation failed: {(p.get('result') or {}).get('error', '')}"[:300])
            if time.monotonic() > deadline:
                raise CloudflareError(f"bulk operation {op_id} still {st} after {self.poll_seconds}s")
            time.sleep(1)

    def apply(self, adds: list[tuple[str, str]], removes: list[Item]) -> None:
        if adds:  # POST appends (PUT would replace the whole list - never used)
            p = self.http.call("POST", self.path + "/items", [{"ip": v, "comment": d} for v, d in adds])
            self._wait(p["result"]["operation_id"])
        if removes:
            p = self.http.call("DELETE", self.path + "/items", {"items": [{"id": i.id} for i in removes]})
            self._wait(p["result"]["operation_id"])


def make_backend(cfg):
    cls = ZeroTrustList if cfg.cf_list_kind == "zerotrust" else RulesList
    return cls(cfg.cf_api_base, cfg.cf_api_token, cfg.cf_account_id, cfg.cf_list_id,
               timeout=cfg.http_timeout, poll_seconds=cfg.bulk_poll_seconds)
