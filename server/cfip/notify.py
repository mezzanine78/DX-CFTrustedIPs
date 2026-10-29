"""ntfy alerts. The bearer token is sent as a header only and never logged."""
from __future__ import annotations

import http.client
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

    def _scrub(self, text: str) -> str:
        """Belt and braces: never let the token reach a log line, whatever an exception message contains."""
        text = str(text)
        return text.replace(self._token, "***") if self._token else text

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
                status, reason = resp.status, getattr(resp, "reason", "")
        except urllib.error.HTTPError as exc:
            status, reason = exc.code, exc.reason
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            detail = getattr(exc, "reason", None) or exc
            log.error("ntfy send failed (network error, alert '%s' not delivered): %s: %s",
                      title, type(exc).__name__, self._scrub(detail))
            return False
        if 200 <= status < 300:
            return True
        hint = ""
        if status in (401, 403):
            hint = (" - NTFY_TOKEN is likely invalid/expired or lacks write access to the topic"
                    + ("" if self._token else " (NTFY_TOKEN is empty)"))
        elif status == 429:
            hint = " - rate limited by the ntfy server"
        elif status >= 500:
            hint = " - ntfy server error, try again later"
        log.error("ntfy send failed (alert '%s' not delivered): HTTP %s %s%s",
                  title, status, self._scrub(reason or ""), hint)
        return False
