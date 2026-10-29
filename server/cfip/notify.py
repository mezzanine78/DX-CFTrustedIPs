"""ntfy alerts. The bearer token is sent as a header only and never logged."""
from __future__ import annotations

import logging
import urllib.error
import urllib.request

log = logging.getLogger("cfip.notify")


class Notifier:
    def __init__(self, url: str, token: str, timeout: int = 15, enabled: bool = True):
        self.url = url
        self._token = token
        self.timeout = timeout
        self.enabled = enabled and bool(url)
        self.sent: list[dict] = []  # recent alerts, handy for tests and /healthz

    def send(self, title: str, message: str, priority: int = 3, tags: str = "") -> bool:
        title = "DX CF-IP: " + title
        rec = {"title": title, "message": message, "priority": priority}
        self.sent = (self.sent + [rec])[-50:]
        if not self.enabled:
            log.info("ntfy disabled; would send p%s %s", priority, title)
            return False
        headers = {"Title": title.encode("utf-8").decode("latin-1", "replace"),
                   "Priority": str(priority), "Content-Type": "text/plain; charset=utf-8"}
        if tags:
            headers["Tags"] = tags
        if self._token:
            headers["Authorization"] = "Bearer " + self._token
        req = urllib.request.Request(self.url, data=message.encode("utf-8"), headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 (configured URL)
                ok = 200 <= resp.status < 300
        except (urllib.error.URLError, OSError) as exc:
            log.error("ntfy send failed: %s", type(exc).__name__)
            return False
        if not ok:
            log.error("ntfy returned non-2xx")
        return ok
