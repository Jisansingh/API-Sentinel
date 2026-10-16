"""Sentinel's own API is never recorded as monitored traffic; the monitored API still is.

Drift guard: every /api/* route the app registers must be a self route, so a new
internal endpoint cannot silently start polluting inventory, shadow-API and
runtime-baseline data with the dashboard's own calls.
"""

import sqlite3

from fastapi.testclient import TestClient

from app.discovery import is_self_route
from app.main import create_app

KEY = "k" * 40


def _app(tmp_path):
    return create_app(db_path=str(tmp_path / "s.db"), api_key=KEY, enable_demo=True)


def _captured(app):
    with sqlite3.connect(app.state.db_path) as conn:
        return [r[0] for r in conn.execute("SELECT path FROM captured_requests ORDER BY id")]


def test_every_registered_api_route_is_excluded_and_demo_routes_are_not(tmp_path):
    paths = set(_app(tmp_path).openapi()["paths"])
    api = {p for p in paths if p.startswith("/api/")}
    assert {"/api/source-scan", "/api/source-scan/upload", "/api/source-apis", "/api/runtime/baselines"} <= api
    assert [p for p in api if not is_self_route(p)] == []
    assert [p for p in paths if p.startswith("/shop/") and is_self_route(p)] == []


def test_prefixes_match_whole_segments_only():
    assert is_self_route("/api/source-scan") and is_self_route("/api/source-scan/upload")
    assert is_self_route("/api/source-apis?project_id=x") and is_self_route("/api/runtime/baselines?days=7")
    for other in ("/api/source-scanner", "/api/source-apis-extra", "/api/runtime", "/api/runtime/other",
                  "/shop/api/source-scan", "/api/runtime/baselines-old"):
        assert not is_self_route(other), other


def test_internal_requests_are_not_captured_but_demo_traffic_is(tmp_path):
    app = _app(tmp_path)
    c = TestClient(app, headers={"X-Sentinel-Key": KEY})
    c.get("/api/runtime/baselines")
    c.get("/api/source-apis", params={"project_id": "demo"})
    c.post("/api/source-scan", json={"source_type": "local", "local_path": "/nonexistent"})  # 400, still internal
    c.post("/api/source-scan/upload", content=b"not a zip", headers={"Content-Type": "application/zip"})
    assert _captured(app) == []
    c.get("/shop/products/3")
    c.get("/shop/me", headers={"Authorization": "Bearer demo-alice-token"})
    assert _captured(app) == ["/shop/products/3", "/shop/me"]
