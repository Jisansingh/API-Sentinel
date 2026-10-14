"""Temporary demo server: serves index.html and proxies /api/* and the demo
shop's /shop/* (monitored traffic, GET only) to the backend.

Same-origin proxy so the demo needs no CORS change in the FastAPI app.
Standard library only. Not the real frontend; safe to delete.

Auth: if SENTINEL_API_KEY is set in this process's environment, the proxy
adds it as X-Sentinel-Key to allowlisted Sentinel routes only (never to
monitored-traffic paths). The key stays server-side: it is never sent to the
browser, written to the page, or logged. Writes (scan, alert triage) must come
from this page's own Origin with a JSON body, so other sites cannot use the
proxy's credentials (CSRF).

Usage:
    python3 demo/serve.py            # demo on :8080, backend on :8000
    BACKEND_URL=http://127.0.0.1:9000 DEMO_PORT=8081 python3 demo/serve.py
    SENTINEL_API_KEY=... python3 demo/serve.py   # same key as the backend
"""

import os
import re
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BACKEND_URL = os.getenv("BACKEND_URL", "http://127.0.0.1:8000").rstrip("/")
DEMO_PORT = int(os.getenv("DEMO_PORT", "8080"))
DEMO_DIR = Path(__file__).resolve().parent
# Reject other Host headers so a DNS-rebinding page cannot reach the proxy.
ALLOWED_HOSTS = {f"127.0.0.1:{DEMO_PORT}", f"localhost:{DEMO_PORT}"}
ALLOWED_ORIGINS = {f"http://{host}" for host in ALLOWED_HOSTS}
API_KEY = os.getenv("SENTINEL_API_KEY") or None
MAX_BODY_BYTES = 4096
# Sentinel routes that get the admin key. Other GET /api/* paths are proxied
# without it (sample "monitored" traffic); other writes are not proxied.
KEYED_ROUTES = {
    "GET": re.compile(r"^/api/(inventory|findings|shadow-apis|alerts)$"),
    "POST": re.compile(r"^/api/scan$"),
    "PATCH": re.compile(r"^/api/alerts/\d+$"),
}


class DemoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DEMO_DIR), **kwargs)

    def log_message(self, format, *args):
        # Drop query strings from the console log: they may carry tokens.
        line = format % args
        super().log_message("%s", re.sub(r"\?\S*", "?[REDACTED]", line))

    def do_HEAD(self):
        self.send_error(405)

    def do_GET(self):
        if self.headers.get("Host") not in ALLOWED_HOSTS:
            self.send_error(403, "demo is localhost-only")
            return
        if self.path.startswith("/shop/"):
            # Demo target API = monitored traffic: pass the client's own
            # Authorization through, never the Sentinel key.
            self._proxy("GET", forward_auth=True)
            return
        if not self.path.startswith("/api/"):
            if self.path not in ("/", "/index.html"):
                self.send_error(404)  # serve only the page, never serve.py
                return
            return super().do_GET()
        self._proxy("GET")

    def do_POST(self):
        self._write("POST")

    def do_PATCH(self):
        self._write("PATCH")

    def _write(self, method):
        if self.headers.get("Host") not in ALLOWED_HOSTS:
            self.send_error(403, "demo is localhost-only")
            return
        if not KEYED_ROUTES[method].match(self.path.split("?", 1)[0]):
            self.send_error(404)
            return
        # CSRF: browsers always send Origin on cross-origin writes.
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            self.send_error(403, "cross-origin write refused")
            return
        # JSON forces a CORS preflight; form/text "simple requests" cannot set it.
        if self.headers.get("Content-Type", "").split(";")[0].strip() != "application/json":
            self.send_error(415, "application/json required")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= MAX_BODY_BYTES:
            self.send_error(413)
            return
        self._proxy(method, self.rfile.read(length))

    def _proxy(self, method, body=None, forward_auth=False):
        headers = {"Content-Type": "application/json"} if body is not None else {}
        if forward_auth and self.headers.get("Authorization"):
            headers["Authorization"] = self.headers["Authorization"]
        elif API_KEY and KEYED_ROUTES[method].match(self.path.split("?", 1)[0]):
            headers["X-Sentinel-Key"] = API_KEY
        req = urllib.request.Request(
            BACKEND_URL + self.path, data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status, body = resp.status, resp.read()
                ctype = resp.headers.get("Content-Type", "application/json")
        except urllib.error.HTTPError as err:  # pass backend 4xx/5xx through
            status, body = err.code, err.read()
            ctype = err.headers.get("Content-Type", "application/json")
        except OSError as err:
            status, ctype = 502, "application/json"
            body = ('{"detail": "backend unreachable: %s"}' % type(err).__name__).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    print(f"API Sentinel demo: http://127.0.0.1:{DEMO_PORT}  (backend {BACKEND_URL})")
    print("Sentinel API key: " + ("configured" if API_KEY else "NOT set (protected routes will return 401/503)"))
    ThreadingHTTPServer(("127.0.0.1", DEMO_PORT), DemoHandler).serve_forever()
