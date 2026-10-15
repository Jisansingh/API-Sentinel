"""Authentication for Sentinel's own API (X-Sentinel-Key)."""

import logging

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

KEY = "k" * 40
READS = ("/api/inventory", "/api/findings", "/api/shadow-apis", "/api/alerts")


def _client(tmp_path, **kw):
    return TestClient(create_app(db_path=str(tmp_path / "auth.db"), **kw))


def test_with_key_every_sentinel_route_requires_it_except_health(tmp_path):
    client = _client(tmp_path, api_key=KEY)
    assert client.get("/api/health").status_code == 200
    for route in READS:
        assert client.get(route).status_code == 401, route
        assert client.get(route, headers={"X-Sentinel-Key": "wrong" * 8}).status_code == 401
        assert client.get(route, headers={"X-Sentinel-Key": KEY}).status_code == 200
    assert client.post("/api/scan").status_code == 401
    assert client.patch("/api/alerts/1", json={"status": "resolved"}).status_code == 401
    assert client.post("/api/scan", headers={"X-Sentinel-Key": KEY}).status_code == 200
    # Authorized but missing alert -> 404 (auth runs first, then the route).
    assert client.patch(
        "/api/alerts/1", json={"status": "resolved"}, headers={"X-Sentinel-Key": KEY}
    ).status_code == 404


def test_without_key_reads_open_writes_fail_closed(tmp_path, caplog):
    with caplog.at_level(logging.WARNING):
        client = _client(tmp_path)
    assert "SENTINEL_API_KEY is not set" in caplog.text
    for route in READS:
        assert client.get(route).status_code == 200, route
    assert client.post("/api/scan").status_code == 503
    assert client.patch("/api/alerts/1", json={"status": "resolved"}).status_code == 503


def test_short_api_key_refuses_to_start(tmp_path):
    with pytest.raises(ValueError, match="at least 32"):
        create_app(db_path=str(tmp_path / "weak.db"), api_key="short")


def test_api_key_never_echoed_in_errors_or_openapi(tmp_path):
    client = _client(tmp_path, api_key=KEY)
    body = client.get("/api/alerts", headers={"X-Sentinel-Key": "x"}).text
    assert KEY not in body
    assert KEY not in client.get("/openapi.json").text


def test_unauthorized_requests_are_not_captured_as_traffic(tmp_path):
    """Brute-forcing Sentinel's key must not pollute the monitored inventory."""
    client = _client(tmp_path, api_key=KEY)
    for _ in range(20):
        client.post("/api/scan")
    items = client.get("/api/inventory", headers={"X-Sentinel-Key": KEY}).json()["items"]
    assert items == []
