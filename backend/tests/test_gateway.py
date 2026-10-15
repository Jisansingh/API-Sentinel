"""Phase 4: reverse proxy / API firewall, plus its integration with detection."""

import json
import logging
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

import app.gateway as gw
from app.capture import credential_fingerprint
from app.main import create_app

FP, ADMIN = "f" * 40, "a" * 40
VP, USER, SCAN = "Bearer gw-vp-secret", "Bearer gw-user-secret", "Bearer gw-scan-secret"


def fp(credential):
    return credential_fingerprint({"authorization": credential}, FP.encode())


PRINCIPALS = {"principals": [
    {"id": "vera", "fingerprint": fp(VP), "role": "vp"},
    {"id": "ulf", "fingerprint": fp(USER), "role": "user"},
    {"id": "scanner", "fingerprint": fp(SCAN), "role": "user", "purpose": "security_scan"},
]}


class Upstream(BaseHTTPRequestHandler):
    hits: list = []

    def _reply(self, status, body=b'{"ok": true}', headers=()):
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        Upstream.hits.append({"path": self.path, "headers": dict(self.headers)})
        if self.path.startswith("/redirect"):
            return self._reply(302, b"", [("Location", "http://169.254.169.254/latest/meta-data/")])
        if self.path.startswith("/boom"):
            return self._reply(500, b"Traceback: secret internal detail")
        if self.path.startswith("/big"):
            return self._reply(200, b"x" * 5000)
        if self.path.startswith("/slow"):
            time.sleep(1.5)
        body = json.dumps({"path": self.path, "headers": dict(self.headers)}).encode()
        self._reply(200, body, [("Set-Cookie", "upstream=1"), ("Server", "secret-version")])

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(length)
        Upstream.hits.append({"path": self.path, "body": data})
        self._reply(201, json.dumps({"received": len(data)}).encode())

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def upstream():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


ROUTES = [
    {"method": "GET", "path": "/shop/products/{id}", "auth": "none"},
    {"method": "GET", "path": "/shop/orders/{id}", "auth": "principal"},
    {"method": "GET", "path": "/admin/report", "auth": "principal", "roles": ["user"]},
    {"method": "GET", "path": "/vp/board", "auth": "principal", "roles": ["vp"]},
    {"method": "POST", "path": "/upload", "auth": "principal"},
    {"method": "GET", "path": "/redirect", "auth": "none"},
    {"method": "GET", "path": "/boom", "auth": "none"},
    {"method": "GET", "path": "/big", "auth": "none"},
    {"method": "GET", "path": "/slow", "auth": "none"},
]


@pytest.fixture
def make(tmp_path, upstream):
    Upstream.hits.clear()

    def build(limits=None, **cfg):
        config = {"upstream": upstream, "allow_private_network": True, "routes": ROUTES, **cfg}
        app = create_app(db_path=str(tmp_path / "gw.db"), fp_secret=FP, api_key=ADMIN,
                         principals=PRINCIPALS, gateway=config, rate_limits=limits)
        return app, TestClient(app)
    return build


def events(app):
    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM gateway_events")]


# --- forwarding and allowlist --------------------------------------------------------------

def test_allowed_route_is_forwarded_with_safe_headers(make, upstream):
    _, c = make()
    r = c.get("/gateway/shop/products/7?q=1", headers={
        "X-Sentinel-Key": ADMIN, "Cookie": "session=abc", "X-Forwarded-For": "6.6.6.6",
        "Authorization": "Bearer passthrough"})
    assert r.status_code == 200
    seen = r.json()
    assert seen["path"] == "/shop/products/7?q=1"
    sent = {k.lower(): v for k, v in seen["headers"].items()}
    assert sent["host"] == upstream.removeprefix("http://")
    assert sent["x-forwarded-for"] == "testclient"  # overwritten, never the client's value
    assert sent["authorization"] == "Bearer passthrough"
    assert "x-sentinel-key" not in sent and "cookie" not in sent
    assert "set-cookie" not in r.headers and r.headers.get("server") != "secret-version"
    assert r.headers["x-ratelimit-limit"] == "60"


@pytest.mark.parametrize("method,path,status", [
    ("GET", "/gateway/not/listed", 404),
    ("DELETE", "/gateway/shop/products/1", 405),
    ("GET", "/gateway/shop/products/1/", 400),
    ("GET", "/gateway/shop/products/%2e%2e", 400),
    ("GET", "/gateway/shop/products/..%2fadmin", 400),
    ("GET", "/gateway/shop/products/1%00", 400),
    ("GET", "/gateway//169.254.169.254/latest", 400),
    ("GET", "/gateway/shop/products/a\\b", 400),
    ("GET", "/gateway/shop/products/1?x=a%0d%0aHost:evil", 200),  # query stays a query
])
def test_firewall_blocks_unlisted_and_malformed_requests(make, method, path, status):
    _, c = make()
    r = c.request(method, path)
    assert r.status_code == status
    if status != 200:
        assert Upstream.hits == [] and set(r.json()) == {"detail"}


def test_client_cannot_choose_host_port_or_scheme(make, upstream):
    _, c = make()
    for path in ("/gateway/shop/products/1?url=http://169.254.169.254/",
                 "/gateway/shop/products/@evil.example"):
        c.get(path)
    assert all(h["path"].startswith("/shop/products/") for h in Upstream.hits)


# --- SSRF / DNS rebinding / redirects --------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://169.254.169.254", "http://[::ffff:169.254.169.254]", "http://100.100.100.200",
    "http://[fd00:ec2::254]", "http://0.0.0.0", "http://224.0.0.1", "http://8.8.8.8",
    "file:///etc/passwd", "gopher://127.0.0.1", "http://user:pw@127.0.0.1", "http://127.0.0.1/api",
    "http://127.0.0.1?x=1", "http://127.0.0.1:99999",
])
def test_unsafe_upstream_configs_are_rejected(tmp_path, url):
    with pytest.raises(ValueError):
        create_app(db_path=str(tmp_path / "x.db"), gateway={
            "upstream": url, "allow_private_network": True,
            "routes": [{"method": "GET", "path": "/a", "auth": "none"}]})


def test_private_upstream_needs_explicit_opt_in(tmp_path):
    with pytest.raises(ValueError, match="allow_private_network"):
        create_app(db_path=str(tmp_path / "x.db"), gateway={
            "upstream": "http://10.0.0.5", "routes": [{"method": "GET", "path": "/a", "auth": "none"}]})


@pytest.mark.parametrize("answers", [
    ["169.254.169.254"],                     # name resolves to cloud metadata
    ["127.0.0.1", "169.254.169.254"],        # rebinding: one good, one bad record
    ["::ffff:169.254.169.254"],
    ["93.184.216.34"],                       # public address over plain http
])
def test_resolved_addresses_are_checked_on_every_request(tmp_path, monkeypatch, answers):
    calls = []
    monkeypatch.setattr(gw, "resolve_host", lambda host, port: answers)
    monkeypatch.setattr(gw.socket, "create_connection", lambda *a, **k: calls.append(a))
    app = create_app(db_path=str(tmp_path / "x.db"), gateway={
        "upstream": "http://upstream.internal:8080", "allow_private_network": True,
        "routes": [{"method": "GET", "path": "/a", "auth": "none"}]})
    r = TestClient(app).get("/gateway/a")
    assert r.status_code == 502 and r.json() == {"detail": "upstream not allowed"}
    assert calls == []
    assert events(app)[0]["reason"] == "upstream_address_refused"


def test_private_hostname_refused_without_opt_in(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "resolve_host", lambda host, port: ["127.0.0.1"])
    app = create_app(db_path=str(tmp_path / "x.db"), gateway={
        "upstream": "http://upstream.internal", "routes": [{"method": "GET", "path": "/a", "auth": "none"}]})
    assert TestClient(app).get("/gateway/a").status_code == 502


def test_connection_is_pinned_to_the_checked_address(tmp_path, monkeypatch, upstream):
    port = int(upstream.rsplit(":", 1)[1])
    monkeypatch.setattr(gw, "resolve_host", lambda host, p: ["127.0.0.1"])
    app = create_app(db_path=str(tmp_path / "x.db"), gateway={
        "upstream": f"http://upstream.internal:{port}", "allow_private_network": True,
        "routes": [{"method": "GET", "path": "/shop/products/{id}", "auth": "none"}]})
    r = TestClient(app).get("/gateway/shop/products/1")
    assert r.status_code == 200 and r.json()["headers"]["Host"] == f"upstream.internal:{port}"


def test_redirects_are_not_followed(make):
    app, c = make()
    r = c.get("/gateway/redirect")
    assert r.status_code == 502 and "location" not in r.headers
    assert [h["path"] for h in Upstream.hits] == ["/redirect"]
    assert any(e["reason"] == "upstream_redirect" for e in events(app))


def test_upstream_errors_are_generic(make):
    _, c = make()
    r = c.get("/gateway/boom")
    assert r.status_code == 500 and r.json() == {"detail": "upstream error"}
    assert "Traceback" not in r.text


# --- size limits and timeouts ------------------------------------------------------------------

def test_request_body_limits(make):
    _, c = make(max_request_body_bytes=10)
    auth = {"Authorization": USER}
    assert c.post("/gateway/upload", content=b"0123456789", headers=auth).status_code == 201
    assert c.post("/gateway/upload", content=b"x" * 11, headers=auth).status_code == 413
    chunked = c.post("/gateway/upload", content=iter([b"x" * 6, b"x" * 6]), headers=auth)
    assert chunked.status_code == 413
    assert [len(h["body"]) for h in Upstream.hits] == [10]


def test_header_and_url_limits(make):
    _, c = make()
    assert c.get("/gateway/shop/products/1", headers={"X-Big": "x" * 17000}).status_code == 431
    assert c.get("/gateway/shop/products/1?" + "a" * 2100).status_code == 414
    assert Upstream.hits == []


def test_response_size_and_timeouts(make):
    _, c = make(max_response_body_bytes=1000, total_timeout_seconds=0.5)
    assert c.get("/gateway/big").status_code == 502
    assert c.get("/gateway/slow").status_code == 504


# --- authentication, authorization, quotas ---------------------------------------------------

def test_principal_routes_need_a_registered_credential(make):
    _, c = make()
    assert c.get("/gateway/shop/orders/1").status_code == 401
    assert c.get("/gateway/shop/orders/1", headers={"Authorization": "Bearer unknown"}).status_code == 401
    assert c.get("/gateway/shop/orders/1", headers={"X-Role": "vp", "X-User": "vera"}).status_code == 401
    assert c.get("/gateway/shop/orders/1", headers={"Authorization": USER}).status_code == 200


def test_vp_does_not_bypass_route_permissions(make):
    app, c = make()
    assert c.get("/gateway/admin/report", headers={"Authorization": VP}).status_code == 403
    assert c.get("/gateway/admin/report", headers={"Authorization": USER}).status_code == 200
    assert c.get("/gateway/vp/board", headers={"Authorization": USER, "X-Role": "vp"}).status_code == 403
    assert c.get("/gateway/vp/board", headers={"Authorization": VP}).status_code == 200
    denied = [e for e in events(app) if e["reason"] == "role_forbidden"]
    assert {(e["principal_id"], e["role"]) for e in denied} == {("vera", "vp"), ("ulf", "user")}


def test_gateway_endpoints_have_their_own_limits_and_vp_21x(make):
    app, c = make({"limits": {"GET /gateway/shop/orders/{id}": 2, "GET /gateway/shop/products/{id}": 4}})
    user, vp = {"Authorization": USER}, {"Authorization": VP}
    assert [c.get("/gateway/shop/orders/1", headers=user).status_code for _ in range(3)] == [200, 200, 429]
    assert [c.get("/gateway/shop/orders/1", headers=vp).status_code for _ in range(43)] == [200] * 42 + [429]
    r = c.get("/gateway/shop/orders/1", headers=user)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    assert [c.get(f"/gateway/shop/products/{i}").status_code for i in range(5)] == [200] * 4 + [429]
    limits = {i["endpoint"]: i for i in c.get("/api/rate-limits", headers={"X-Sentinel-Key": ADMIN}).json()["items"]}
    assert limits["GET /gateway/shop/orders/{id}"]["vp_limit"] == 42
    assert limits["GET /gateway/admin/report"]["normal_limit"] == 60  # default_limit


def test_unknown_routes_share_one_quota(make):
    _, c = make({"default_limit": 3})
    codes = [c.get(f"/gateway/probe/{i}").status_code for i in range(5)]
    assert codes == [404, 404, 404, 429, 429]


def test_scanner_traffic_is_labelled(make):
    app, c = make()
    c.get("/gateway/shop/orders/1", headers={"Authorization": SCAN})
    c.get("/gateway/shop/orders/1", headers={"Authorization": VP})
    labels = {(e["principal_id"], e["reason"]) for e in events(app)}
    assert ("scanner", "security_scan") in labels and ("vera", "vp_quota") in labels
    listed = c.get("/api/gateway-events", headers={"X-Sentinel-Key": ADMIN}).json()
    assert listed["total"] == len(events(app))


def test_gateway_config_validation(tmp_path):
    base = {"upstream": "http://127.0.0.1:9", "allow_private_network": True}
    bad = [
        {"routes": []},
        {"routes": [{"method": "TRACE", "path": "/a", "auth": "none"}]},
        {"routes": [{"method": "GET", "path": "/a/../b", "auth": "none"}]},
        {"routes": [{"method": "GET", "path": "a", "auth": "none"}]},
        {"routes": [{"method": "GET", "path": "/a", "auth": "none", "roles": ["vp"]}]},
        {"routes": [{"method": "GET", "path": "/a", "auth": "principal", "roles": ["root"]}]},
        {"routes": [{"method": "GET", "path": "/a", "auth": "none"}] * 2},
        {"routes": [{"method": "GET", "path": "/a", "auth": "none"}], "total_timeout_seconds": 0},
        {"routes": [{"method": "GET", "path": "/a", "auth": "none"}], "allow_private_network": "yes"},
    ]
    for extra in bad:
        with pytest.raises(ValueError):
            create_app(db_path=str(tmp_path / "x.db"), gateway={**base, **extra})
    with pytest.raises(ValueError, match="PRINCIPALS"):
        create_app(db_path=str(tmp_path / "x.db"), gateway={
            **base, "routes": [{"method": "GET", "path": "/a"}]})  # auth defaults to principal


# --- logging, capture and detection integration ------------------------------------------------

def test_logs_and_storage_never_hold_credentials_or_query_secrets(make, caplog):
    app, c = make({"limits": {"GET /gateway/shop/orders/{id}": 1}})
    caplog.set_level(logging.INFO)
    for _ in range(2):
        c.get("/gateway/shop/orders/1?token=gw-query-secret", headers={"Authorization": VP})
        c.get("/gateway/shop/orders/1?api_key=gw-query-secret", headers={"Authorization": USER})
    c.get("/gateway/admin/report", headers={"Authorization": VP})
    raw = open(app.state.db_path, "rb").read()
    # httpx (the test client itself) logs the URL it sent; only server-side loggers count.
    server_logs = "\n".join(r.getMessage() for r in caplog.records if not r.name.startswith("httpx"))
    assert "access_control" in server_logs
    for secret in ("gw-vp-secret", "gw-user-secret", "gw-query-secret"):
        assert secret.encode() not in raw and secret not in server_logs
    paths = [r[0] for r in sqlite3.connect(app.state.db_path).execute("SELECT path FROM captured_requests")]
    assert paths and all(p.startswith("/shop/") or p.startswith("/admin/") for p in paths)


def test_gateway_traffic_feeds_inventory_and_detection(make):
    app, c = make()
    for i in range(1, 16):  # 15 distinct product pages in a burst = scraping
        assert c.get(f"/gateway/shop/products/{i}").status_code == 200
    key = {"X-Sentinel-Key": ADMIN}
    inventory = c.get("/api/inventory", headers=key).json()
    assert {(i["method"], i["path"]) for i in inventory["items"]} == {("GET", "/shop/products/{id}")}
    scan = c.post("/api/scan", headers=key, json={}).json()
    assert scan["created"] >= 1
    alerts = c.get("/api/alerts", headers=key).json()["items"]
    assert any(a["detection_type"] == "scraping" and a["endpoint"] == "/shop/products/{id}" for a in alerts)


def test_firewall_rejected_paths_are_not_captured_as_api_traffic(make):
    app, c = make()
    for path in ("/gateway/shop/products/%2e%2e%2fadmin", "/gateway/not/listed", "/gateway/x/../y"):
        c.get(path)
    c.request("DELETE", "/gateway/shop/products/1")
    c.get("/gateway/shop/products/1")
    rows = sqlite3.connect(app.state.db_path).execute("SELECT method, path FROM captured_requests").fetchall()
    assert rows == [("GET", "/shop/products/1")]
    blocked = {e["reason"] for e in events(app) if e["decision"] == "blocked"}
    assert {"invalid_path", "route_not_allowed", "method_not_allowed"} <= blocked


@pytest.mark.parametrize("addr,scheme,private,ok", [
    ("127.0.0.1", "http", True, True), ("::1", "http", True, True), ("::1", "https", False, False),
    ("10.1.2.3", "http", True, True), ("10.1.2.3", "https", False, False),
    ("169.254.169.254", "https", True, False), ("fe80::1", "https", True, False),
    ("::ffff:169.254.169.254", "https", True, False), ("fd00:ec2::254", "https", True, False),
    ("100.100.100.200", "https", True, False), ("240.0.0.1", "https", True, False),
    ("93.184.216.34", "https", False, True), ("93.184.216.34", "http", True, False),
])
def test_address_policy(addr, scheme, private, ok):
    import ipaddress
    assert gw.address_allowed(ipaddress.ip_address(addr), scheme, private) is ok


def test_without_gateway_the_prefix_is_ordinary_traffic(tmp_path):
    app = create_app(db_path=str(tmp_path / "x.db"))
    assert TestClient(app).get("/gateway/admin").status_code == 404
    rows = sqlite3.connect(app.state.db_path).execute("SELECT path FROM captured_requests").fetchall()
    assert rows == [("/gateway/admin",)]
