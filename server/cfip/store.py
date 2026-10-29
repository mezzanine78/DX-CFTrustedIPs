"""Persistent state on the /data volume: client registry and per-client IP state.

Files (JSON, written atomically):
  clients.json  {CODE: {name, token_sha256, allowed_cidrs, disabled, created}}
  state.json    {clients: {CODE: {...}}, last_sync: {...}, alerts: {...}}
Tokens are stored only as SHA-256 hashes; the plaintext is shown once at creation.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading

from .config import CODE_RE
from .util import now


class StoreError(RuntimeError):
    pass


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Store:
    def __init__(self, data_dir: str):
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)
        self.lock = threading.RLock()
        self.clients_path = os.path.join(data_dir, "clients.json")
        self.state_path = os.path.join(data_dir, "state.json")

    # ---- low level -------------------------------------------------------
    def _read(self, path: str, default):
        if not os.path.exists(path):
            return copy.deepcopy(default)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, ValueError) as exc:
            # Never treat a corrupt file as empty: that would look like "all clients gone".
            raise StoreError(f"cannot read {os.path.basename(path)}: {exc}") from exc
        if not isinstance(data, dict):
            raise StoreError(f"{os.path.basename(path)} is not a JSON object")
        return data

    def _write(self, path: str, data) -> None:
        fd, tmp = tempfile.mkstemp(dir=self.data_dir, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, 0o600)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise

    # ---- clients ---------------------------------------------------------
    def clients(self) -> dict:
        with self.lock:
            return self._read(self.clients_path, {})

    def save_clients(self, data: dict) -> None:
        with self.lock:
            self._write(self.clients_path, data)

    def add_client(self, code: str, name: str, allowed_cidrs=None) -> str:
        code = code.strip().upper()
        if not CODE_RE.fullmatch(code):
            raise StoreError("client code must be 2-32 chars: A-Z, 0-9, '_' or '-'")
        name = (name or code).strip()[:80]
        with self.lock:
            data = self.clients()
            if code in data:
                raise StoreError(f"client {code} already exists (use rotate)")
            token = secrets.token_urlsafe(32)
            data[code] = {"name": name, "token_sha256": hash_token(token),
                          "allowed_cidrs": list(allowed_cidrs or []), "disabled": False, "created": now()}
            self.save_clients(data)
            return token

    def rotate_client(self, code: str) -> str:
        code = code.strip().upper()
        with self.lock:
            data = self.clients()
            if code not in data:
                raise StoreError(f"unknown client {code}")
            token = secrets.token_urlsafe(32)
            data[code]["token_sha256"] = hash_token(token)
            self.save_clients(data)
            return token

    def set_client(self, code: str, **fields) -> None:
        code = code.strip().upper()
        with self.lock:
            data = self.clients()
            if code not in data:
                raise StoreError(f"unknown client {code}")
            data[code].update(fields)
            self.save_clients(data)

    def remove_client(self, code: str) -> None:
        code = code.strip().upper()
        with self.lock:
            data = self.clients()
            if code not in data:
                raise StoreError(f"unknown client {code}")
            del data[code]
            self.save_clients(data)
            st = self.state()
            st.get("clients", {}).pop(code, None)
            self.save_state(st)

    def verify(self, code: str, token: str) -> dict | None:
        """Constant-time token check. Returns the client record or None."""
        if not isinstance(code, str) or not isinstance(token, str) or not token:
            return None
        rec = self.clients().get(code.strip().upper())
        dummy = "0" * 64
        ok = hmac.compare_digest(hash_token(token), (rec or {}).get("token_sha256", dummy))
        if rec and ok and not rec.get("disabled"):
            return rec
        return None

    # ---- state -----------------------------------------------------------
    def state(self) -> dict:
        with self.lock:
            st = self._read(self.state_path, {"clients": {}, "alerts": {}, "last_sync": {}})
            st.setdefault("clients", {})
            st.setdefault("alerts", {})
            st.setdefault("last_sync", {})
            return st

    def save_state(self, st: dict) -> None:
        with self.lock:
            self._write(self.state_path, st)
