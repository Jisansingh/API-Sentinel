"""Dashboard proxy (demo/serve.py) <-> authenticated Sentinel API, end to end.

Runs the real Sentinel app under uvicorn with SENTINEL_API_KEY enabled and
the real demo proxy handler in front of it, both on loopback ports.
"""

import importlib.util
import json
import socket
import threading
import time
import urllib.error
from urllib.parse import urlencode
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import uvicorn

from app.main import create_app

SERVE_PY = Path(__file__).resolve().parents[2] / "demo" / "serve.py"
API_KEY = "p" * 40


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _load_proxy(monkeypatch, backend_url, port, api_key):
    monkeypatch.setenv("BACKEND_URL", backend_url)
    monkeypatch.setenv("DEMO_PORT", str(port))
    if api_key is None:
        monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    else:
        monkeypatch.setenv("SENTINEL_API_KEY", api_key)
    spec = importlib.util.spec_from_file_location(f"demo_serve_{port}", SERVE_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _start_http(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def backend(tmp_path):
    """Real Sentinel (auth on) under uvicorn; yields base URL."""
    port = _free_port()
    app = create_app(
        db_path=str(tmp_path / "proxy.db"), api_key=API_KEY, fp_secret="f" * 40, enable_demo=True,
        spec_dir=str(SHOP_SPEC.parent),
    )
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


def _proxy(monkeypatch, backend_url, api_key=API_KEY):
    port = _free_port()
    module = _load_proxy(monkeypatch, backend_url, port, api_key)
    server = _start_http(ThreadingHTTPServer(("127.0.0.1", port), module.DemoHandler))
    return server, f"http://127.0.0.1:{port}"


def _call(url, method="GET", body=None, headers=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode()


def _write_headers(origin):
    return {"Origin": origin, "Content-Type": "application/json"}


def test_dashboard_reads_scans_and_triages_through_authenticated_proxy(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend)
    try:
        # Backend really is locked: direct calls without the key are refused.
        assert _call(backend + "/api/inventory")[0] == 401
        assert _call(backend + "/api/scan", "POST")[0] == 401

        # Monitored traffic (no key attached) so there is something to detect.
        for i in range(15):
            _call(f"{base}/api/users/{i}")

        status, body = _call(base + "/api/inventory")
        assert status == 200 and json.loads(body)["total_endpoints"] == 1
        assert _call(base + "/api/findings")[0] == 200
        assert _call(base + "/api/health")[0] == 200

        status, body = _call(base + "/api/scan", "POST", {}, _write_headers(base))
        # 15 distinct IDs, all 404 -> scraping (rate) + BOLA enumeration (denials).
        assert status == 200 and json.loads(body)["created"] == 2
        alerts = json.loads(_call(base + "/api/alerts")[1])["items"]
        assert {a["detection_type"] for a in alerts} == {"scraping", "bola_enumeration"}
        alert_id = alerts[0]["id"]

        status, body = _call(
            f"{base}/api/alerts/{alert_id}", "PATCH",
            {"status": "acknowledged", "note": "triaged in demo"}, _write_headers(base),
        )
        assert status == 200 and json.loads(body)["status"] == "acknowledged"
        assert json.loads(_call(base + "/api/alerts?status=acknowledged")[1])["total"] == 1
    finally:
        server.shutdown()


def test_proxy_rejects_cross_site_and_malformed_writes(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend)
    try:
        # CSRF: a foreign page (or no Origin at all) cannot trigger writes.
        assert _call(base + "/api/scan", "POST", {}, _write_headers("http://evil.example"))[0] == 403
        assert _call(base + "/api/scan", "POST", {}, {"Content-Type": "application/json"})[0] == 403
        # Simple-request content types are refused even from our own origin.
        assert _call(base + "/api/scan", "POST", {}, {"Origin": base, "Content-Type": "text/plain"})[0] == 415
        # Only allowlisted write routes are proxied.
        assert _call(base + "/api/inventory", "POST", {}, _write_headers(base))[0] == 404
        assert _call(base + "/api/alerts/abc", "PATCH", {}, _write_headers(base))[0] == 404
        # Oversized bodies are refused before reaching the backend.
        big = {"status": "open", "note": "x" * 10_000}
        assert _call(base + "/api/alerts/1", "PATCH", big, _write_headers(base))[0] == 413
        # DNS rebinding: wrong Host header is refused for reads and writes.
        assert _call(base + "/api/inventory", headers={"Host": "evil.example"})[0] == 403
        assert _call(base + "/api/scan", "POST", {}, {**_write_headers(base), "Host": "evil.example"})[0] == 403
    finally:
        server.shutdown()


def test_proxy_without_key_gets_401_from_locked_backend(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend, api_key=None)
    try:
        assert _call(base + "/api/inventory")[0] == 401
        assert _call(base + "/api/scan", "POST", {}, _write_headers(base))[0] == 401
        assert _call(base + "/api/health")[0] == 200  # public liveness stays open
    finally:
        server.shutdown()


class _Recorder(BaseHTTPRequestHandler):
    seen: list = []

    auth: list = []

    def _record(self):
        _Recorder.seen.append((self.command, self.path, self.headers.get("X-Sentinel-Key")))
        _Recorder.auth.append(self.headers.get("Authorization"))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    do_GET = do_POST = do_PATCH = _record

    def log_message(self, *args):
        pass


def test_key_only_sent_to_sentinel_routes_and_never_exposed(monkeypatch, capfd):
    _Recorder.seen = []
    stub = _start_http(ThreadingHTTPServer(("127.0.0.1", _free_port()), _Recorder))
    server, base = _proxy(monkeypatch, f"http://127.0.0.1:{stub.server_address[1]}")
    try:
        _call(base + "/api/inventory")
        _call(base + "/api/users/7?token=abc")  # monitored traffic
        _call(base + "/api/health")
        _call(base + "/api/scan", "POST", {}, _write_headers(base))
        _call(base + "/api/alerts/3", "PATCH", {"status": "resolved"}, _write_headers(base))
        sent = {(m, p.split("?")[0]): key for m, p, key in _Recorder.seen}
        assert sent[("GET", "/api/inventory")] == API_KEY
        assert sent[("POST", "/api/scan")] == API_KEY
        assert sent[("PATCH", "/api/alerts/3")] == API_KEY
        assert sent[("GET", "/api/users/7")] is None  # never leaked to monitored routes
        assert sent[("GET", "/api/health")] is None

        status, page = _call(base + "/")
        assert status == 200 and API_KEY not in page
        assert _call(base + "/serve.py")[0] == 404
    finally:
        server.shutdown()
        stub.shutdown()
    out, err = capfd.readouterr()
    assert API_KEY not in out + err  # not in proxy logs
    assert "abc" not in err  # query strings still redacted in logs


def test_key_absent_from_dashboard_source_files():
    for name in ("index.html", "serve.py"):
        assert API_KEY not in (SERVE_PY.parent / name).read_text()
        assert "X-Sentinel-Key" not in (SERVE_PY.parent / "index.html").read_text()


# --- Dashboard "Generate sample traffic" -> expected shadow API ----------------

import re

from app.routes.demo_shop import DEMO_USERS
from simulator.run import SHOP_SPEC


def _sample_traffic_plan():
    """The exact request list the dashboard button replays (embedded JSON)."""
    html = (SERVE_PY.parent / "index.html").read_text()
    match = re.search(
        r'<script type="application/json" id="sample-traffic">(.*?)</script>', html, re.S
    )
    assert match, "index.html must embed the sample-traffic plan"
    return json.loads(match.group(1))


def _replay(base, plan):
    """Send each step the way generateTraffic() does (Authorization only if set)."""
    statuses = {}
    for step in plan:
        headers = {"Authorization": f"Bearer {step['token']}"} if step.get("token") else {}
        statuses[step["path"]] = _call(base + step["path"], headers=headers)[0]
    return statuses


def test_plan_uses_existing_demo_shop_routes_and_public_demo_tokens():
    plan = _sample_traffic_plan()
    assert plan and all(step["path"].startswith("/shop/") for step in plan)
    assert {s["token"] for s in plan if s.get("token")} <= set(DEMO_USERS)
    assert API_KEY not in json.dumps(plan)


def test_dashboard_traffic_generator_produces_internal_export_shadow_api(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend)
    try:
        statuses = _replay(base, _sample_traffic_plan())
        assert statuses["/shop/internal/export"] == 200  # observed AND successful
        assert statuses["/shop/admin/stats"] == 200
        assert all(code == 200 for code in statuses.values()), statuses

        query = urlencode({"spec_path": str(SHOP_SPEC)})
        status, body = _call(base + "/api/shadow-apis?" + query)
        body = json.loads(body)
        assert status == 200 and body["spec_loaded"] is True
        shadow = {(r["method"], r["path"]) for r in body["shadow_apis"]}
        # both deliberately undocumented demo routes, and nothing else
        assert shadow == {("GET", "/shop/internal/export"), ("GET", "/shop/admin/stats")}
        documented = {r["path"] for r in body["documented"]}
        assert not documented & {"/shop/internal/export", "/shop/admin/stats"}
        assert {"/shop/products/{id}", "/shop/me", "/shop/orders/{id}"} <= documented

        # Sentinel's own routes (incl. the shadow-apis call above) stay uncaptured.
        inventory = json.loads(_call(base + "/api/inventory")[1])["items"]
        assert inventory and all(i["path"].startswith("/shop/") for i in inventory)
    finally:
        server.shutdown()


def test_shop_requests_forward_only_client_auth_never_sentinel_key(monkeypatch, capfd):
    _Recorder.seen, _Recorder.auth = [], []
    stub = _start_http(ThreadingHTTPServer(("127.0.0.1", _free_port()), _Recorder))
    server, base = _proxy(monkeypatch, f"http://127.0.0.1:{stub.server_address[1]}")
    try:
        _call(base + "/shop/internal/export", headers={"Authorization": "Bearer demo-alice-token"})
        _call(base + "/shop/products/1", headers={"X-Sentinel-Key": "spoofed"})
    finally:
        server.shutdown()
        stub.shutdown()
    assert [(p, k) for _, p, k in _Recorder.seen] == [
        ("/shop/internal/export", None), ("/shop/products/1", None),
    ]
    assert _Recorder.auth == ["Bearer demo-alice-token", None]
    assert API_KEY not in "".join(capfd.readouterr())


# --- dashboard authentication status ----------------------------------------------

WRONG_KEY = "w" * 40


def test_proxy_status_matching_key_reports_backend_ok(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend, api_key=API_KEY)
    try:
        status, body = _call(base + "/api/proxy-status")
        assert status == 200 and json.loads(body) == {"backend": "ok", "proxy_revision": 2}
        assert _call(base + "/api/inventory")[0] == 200  # sections agree with the status
    finally:
        server.shutdown()


def test_proxy_status_mismatched_key_reports_auth_failed_and_sections_401(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend, api_key=WRONG_KEY)
    try:
        # Health is public, so reachability alone still looks fine.
        assert _call(base + "/api/health")[0] == 200
        status, body = _call(base + "/api/proxy-status")
        assert status == 200 and json.loads(body) == {"backend": "auth_failed", "proxy_revision": 2}
        assert _call(base + "/api/inventory")[0] == 401
        assert _call(base + "/api/alerts")[0] == 401
    finally:
        server.shutdown()


def test_proxy_status_missing_key_reports_auth_failed(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend, api_key=None)
    try:
        status, body = _call(base + "/api/proxy-status")
        assert status == 200 and json.loads(body) == {"backend": "auth_failed", "proxy_revision": 2}
    finally:
        server.shutdown()


def test_proxy_status_reports_unreachable_backend(monkeypatch):
    server, base = _proxy(monkeypatch, f"http://127.0.0.1:{_free_port()}", api_key=API_KEY)
    try:
        status, body = _call(base + "/api/proxy-status")
        assert status == 200 and json.loads(body) == {"backend": "unreachable", "proxy_revision": 2}
        assert _call(base + "/api/health")[0] == 502
    finally:
        server.shutdown()


def test_proxy_status_never_exposes_either_key(monkeypatch, backend):
    for key in (API_KEY, WRONG_KEY, None):
        server, base = _proxy(monkeypatch, backend, api_key=key)
        try:
            body = _call(base + "/api/proxy-status")[1]
            assert API_KEY not in body and WRONG_KEY not in body
        finally:
            server.shutdown()


def test_proxy_status_is_localhost_only(monkeypatch, backend):
    server, base = _proxy(monkeypatch, backend, api_key=API_KEY)
    try:
        assert _call(base + "/api/proxy-status", headers={"Host": "evil.example"})[0] == 403
    finally:
        server.shutdown()
