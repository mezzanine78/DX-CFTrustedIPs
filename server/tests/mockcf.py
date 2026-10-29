"""Local mock of the Cloudflare list APIs (zerotrust + rules) and an ntfy topic."""
from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

ACCOUNT = "a" * 32
ZT_LIST = "f174e90a-fafe-4643-bbbc-4a0ed4fc8415"
RULES_LIST = "b" * 32
TOKEN = "test-cf-token"
NTFY_TOKEN = "test-ntfy-token"


class MockState:
    def __init__(self):
        self.zt_items: list[dict] = []
        self.rules_items: list[dict] = []
        self.ops: dict[str, int] = {}
        self.requests: list[tuple[str, str]] = []
        self.ntfy: list[dict] = []
        self.fail_get = False
        self.fail_write = False
        self.lie_total = False  # report a bigger total_count than returned -> partial read
        self.per_page_cap = 1000


class MockServer:
    def __init__(self):
        self.s = MockState()
        st = self.s

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _ok(self, result, info=None):
                body = {"success": True, "errors": [], "messages": [], "result": result}
                if info is not None:
                    body["result_info"] = info
                self._json(200, body)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n)) if n else None

            def _route(self, method):
                u = urlparse(self.path)
                st.requests.append((method, u.path))
                if u.path == "/ntfy":
                    if self.headers.get("Authorization") != "Bearer " + NTFY_TOKEN:
                        return self._json(401, {"error": "unauthorized"})
                    st.ntfy.append({"title": self.headers.get("Title"), "priority": int(self.headers.get("Priority", 3)),
                                    "body": self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode()})
                    return self._json(200, {"id": "x"})
                if self.headers.get("Authorization") != "Bearer " + TOKEN:
                    return self._json(403, {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]})
                q = parse_qs(u.query)
                zt = f"/client/v4/accounts/{ACCOUNT}/gateway/lists/{ZT_LIST}"
                rl = f"/client/v4/accounts/{ACCOUNT}/rules/lists"
                if method == "GET" and st.fail_get:
                    return self._json(500, {"success": False, "errors": [{"code": 1000, "message": "boom"}]})
                if method != "GET" and st.fail_write:
                    return self._json(500, {"success": False, "errors": [{"code": 1001, "message": "write boom"}]})
                if u.path == zt + "/items" and method == "GET":
                    page, per = int(q.get("page", ["1"])[0]), min(int(q.get("per_page", ["20"])[0]), st.per_page_cap)
                    items = st.zt_items[(page - 1) * per: page * per]
                    total = len(st.zt_items) + (1 if st.lie_total else 0)
                    pages = max(1, -(-total // per))
                    return self._ok(items, {"page": page, "per_page": per, "count": len(items),
                                            "total_count": total, "total_pages": pages})
                if u.path == zt and method == "PATCH":
                    b = self._body() or {}
                    rem = set(b.get("remove") or [])
                    st.zt_items = [i for i in st.zt_items if i["value"] not in rem]
                    for a in b.get("append") or []:
                        if any(i["value"] == a["value"] for i in st.zt_items):
                            return self._json(400, {"success": False, "errors": [{"code": 2001, "message": "duplicate"}]})
                        st.zt_items.append({"value": a["value"], "description": a.get("description", ""),
                                            "created_at": "2026-10-29T00:00:00Z"})
                    return self._ok({"id": ZT_LIST, "count": len(st.zt_items)})
                if u.path == f"{rl}/{RULES_LIST}/items" and method == "GET":
                    per = min(int(q.get("per_page", ["25"])[0]), st.per_page_cap)
                    start = int(q.get("cursor", ["0"])[0])
                    chunk = st.rules_items[start:start + per]
                    nxt = start + per
                    info = {"cursors": {"after": str(nxt)}} if nxt < len(st.rules_items) else {"cursors": {}}
                    return self._ok(chunk, info)
                if u.path == f"{rl}/{RULES_LIST}/items" and method == "POST":
                    for a in self._body() or []:
                        st.rules_items.append({"id": secrets.token_hex(16), "ip": a["ip"], "comment": a.get("comment", "")})
                    op = secrets.token_hex(16)
                    st.ops[op] = 1  # one 'running' poll before completed
                    return self._ok({"operation_id": op})
                if u.path == f"{rl}/{RULES_LIST}/items" and method == "DELETE":
                    ids = {i["id"] for i in (self._body() or {}).get("items", [])}
                    st.rules_items = [i for i in st.rules_items if i["id"] not in ids]
                    op = secrets.token_hex(16)
                    st.ops[op] = 0
                    return self._ok({"operation_id": op})
                if u.path.startswith(f"{rl}/bulk_operations/") and method == "GET":
                    op = u.path.rsplit("/", 1)[1]
                    if st.ops.get(op, 0) > 0:
                        st.ops[op] -= 1
                        return self._ok({"id": op, "status": "running"})
                    return self._ok({"id": op, "status": "completed"})
                return self._json(404, {"success": False, "errors": [{"code": 7003, "message": "no route"}]})

            def do_GET(self):
                self._route("GET")

            def do_POST(self):
                self._route("POST")

            def do_PATCH(self):
                self._route("PATCH")

            def do_DELETE(self):
                self._route("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}/client/v4"
        self.ntfy_url = f"http://127.0.0.1:{self.port}/ntfy"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
