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

import json
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
# Reported by /api/proxy-status so the page can tell when this process is older than
# the dashboard files it serves (they are read from disk, this module is not).
# Bump together with REQUIRED_PROXY_REVISION in dashboard.js when KEYED_ROUTES changes.
PROXY_REVISION = 6
MIN_KEY_LENGTH = 32  # the backend refuses shorter keys, so a shorter one can never work
# The only files served from this folder (never serve.py or anything else).
STATIC_PATHS = ("/", "/index.html", "/dashboard.css", "/dashboard.js")
# No inline script or style anywhere in the page, so scripts/styles may only
# come from this origin and the page may not be framed or post forms.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
# Sentinel routes that get the admin key. Other GET /api/* paths are proxied
# without it (sample "monitored" traffic); other writes are not proxied.
KEYED_ROUTES = {
    "GET": re.compile(r"^/api/(inventory|findings|shadow-apis|alerts|rate-limits|gateway-events|evaluation"
                      r"|source-apis|runtime/baselines|alerts/\d+|incidents|risk/endpoints|runtime/history)$"),
    "POST": re.compile(r"^/api/(scan|evaluation|source-scan|source-scan/upload)$"),
    "PATCH": re.compile(r"^/api/alerts/\d+$"),
}
# Writes whose body is not JSON <= MAX_BODY_BYTES. application/zip is not a CORS-safelisted
# type either, so a cross-site form still cannot send it (plus the Origin check below).
WRITE_BODIES = {"/api/source-scan/upload": ("application/zip", 20 * 1024 * 1024)}
# A public GitHub archive is downloaded and scanned inside the request.
SLOW_ROUTES = {"/api/source-scan", "/api/source-scan/upload"}


class DemoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DEMO_DIR), **kwargs)

    def end_headers(self):
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        super().end_headers()

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
        if self.path == "/api/proxy-status":
            body = json.dumps({"backend": backend_auth_status(), "proxy_revision": PROXY_REVISION}).encode()
            self._send(200, "application/json", body)
            return
        if not self.path.startswith("/api/"):
            if self.path not in STATIC_PATHS:
                self.send_error(404)  # serve only the dashboard files, never serve.py
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
        route = self.path.split("?", 1)[0]
        if not KEYED_ROUTES[method].match(route):
            self.send_error(404)
            return
        ctype, limit = WRITE_BODIES.get(route, ("application/json", MAX_BODY_BYTES))
        # CSRF: browsers always send Origin on cross-origin writes.
        if self.headers.get("Origin") not in ALLOWED_ORIGINS:
            self.send_error(403, "cross-origin write refused")
            return
        # JSON forces a CORS preflight; form/text "simple requests" cannot set it.
        if self.headers.get("Content-Type", "").split(";")[0].strip() != ctype:
            self.send_error(415, f"{ctype} required")
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = -1
        if not 0 <= length <= limit:
            self.send_error(413)
            return
        self._proxy(method, self.rfile.read(length), ctype=ctype)

    def _send(self, status, ctype, body):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self, method, body=None, forward_auth=False, ctype="application/json"):
        route = self.path.split("?", 1)[0]
        headers = {"Content-Type": ctype} if body is not None else {}
        if forward_auth and self.headers.get("Authorization"):
            headers["Authorization"] = self.headers["Authorization"]
        elif API_KEY and KEYED_ROUTES[method].match(route):
            headers["X-Sentinel-Key"] = API_KEY
        req = urllib.request.Request(
            BACKEND_URL + self.path, data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req, timeout=120 if route in SLOW_ROUTES else 10) as resp:
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


def backend_auth_status():
    """Does the backend accept this proxy's key? One of ok / auth_failed / unreachable.

    Probes a protected read, so the answer matches what the dashboard's sections
    get. Returns only the word, never the key or the backend's response body.
    """
    headers = {"X-Sentinel-Key": API_KEY} if API_KEY else {}
    req = urllib.request.Request(BACKEND_URL + "/api/inventory", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=3):
            return "ok"
    except urllib.error.HTTPError as err:
        return "auth_failed" if err.code == 401 else "error"
    except OSError:
        return "unreachable"


def check_backend_key():
    """One-line startup verdict on the key; never contains the key itself.

    A key the backend rejects is the usual cause of "401" in the dashboard
    (proxy and backend started with different SENTINEL_API_KEY values).
    """
    if not API_KEY:
        return "NOT set (protected routes will return 401/503)"
    if len(API_KEY) < MIN_KEY_LENGTH:
        return f"set but shorter than {MIN_KEY_LENGTH} characters: the backend will reject it"
    req = urllib.request.Request(BACKEND_URL + "/api/inventory", headers={"X-Sentinel-Key": API_KEY})
    try:
        with urllib.request.urlopen(req, timeout=3):
            return "configured and accepted by the backend"
    except urllib.error.HTTPError as err:
        if err.code == 401:
            return "REJECTED by the backend (401): it does not match the backend's SENTINEL_API_KEY"
        return f"configured (backend answered HTTP {err.code} to the check)"
    except OSError:
        return "configured (backend not reachable yet, key not checked)"


if __name__ == "__main__":
    print(f"API Sentinel demo: http://127.0.0.1:{DEMO_PORT}  (backend {BACKEND_URL})")
    print("Sentinel API key: " + check_backend_key())
    ThreadingHTTPServer(("127.0.0.1", DEMO_PORT), DemoHandler).serve_forever()
