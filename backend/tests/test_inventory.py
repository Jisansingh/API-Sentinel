"""Inventory aggregation endpoint tests."""

from fastapi.testclient import TestClient

from app.main import create_app
from app.storage import init_db, save_captured_request


def _seed(db_file: str) -> None:
    init_db(db_file)
    save_captured_request(
        db_file, method="GET", path="/users/101", status_code=200,
        duration_ms=1.0, client_ip="t",
    )
    save_captured_request(
        db_file, method="GET", path="/users/202", status_code=200,
        duration_ms=2.0, client_ip="t",
    )
    save_captured_request(
        db_file, method="GET", path="/users/search?next=/x",
        status_code=200, duration_ms=1.5, client_ip="t",
    )
    save_captured_request(
        db_file, method="POST", path="/users/101", status_code=404,
        duration_ms=1.0, client_ip="t",
    )


def test_inventory_aggregates_by_method_and_normalized_path(tmp_path):
    db_file = str(tmp_path / "inv.db")
    _seed(db_file)
    client = TestClient(create_app(db_path=db_file))

    response = client.get("/api/inventory")

    assert response.status_code == 200
    body = response.json()
    by_key = {(i["method"], i["path"]): i for i in body["items"]}

    assert by_key[("GET", "/users/{id}")]["request_count"] == 2
    assert by_key[("GET", "/users/search")]["request_count"] == 1
    assert by_key[("POST", "/users/{id}")]["request_count"] == 1
    assert body["total_requests"] == 4
    assert body["total_endpoints"] == 3


def test_inventory_reports_status_and_params(tmp_path):
    db_file = str(tmp_path / "inv.db")
    _seed(db_file)
    client = TestClient(create_app(db_path=db_file))

    item = next(
        i
        for i in client.get("/api/inventory").json()["items"]
        if (i["method"], i["path"]) == ("GET", "/users/search")
    )

    assert item["status_codes"] == [200]
    assert item["last_status"] == 200
    assert item["last_seen"]  # non-empty timestamp string
    assert item["query_params"] == ["next"]  # names only, never values


def test_inventory_never_exposes_secrets(tmp_path):
    db_file = str(tmp_path / "inv.db")
    init_db(db_file)
    save_captured_request(
        db_file, method="GET", path="/login?password=hunter2",
        status_code=200, duration_ms=1.0, client_ip="t",
    )
    client = TestClient(create_app(db_path=db_file))

    blob = client.get("/api/inventory").text

    assert "hunter2" not in blob


def test_empty_inventory_returns_empty_list(tmp_path):
    db_file = str(tmp_path / "empty.db")
    client = TestClient(create_app(db_path=db_file))

    response = client.get("/api/inventory")

    assert response.status_code == 200
    assert response.json() == {"items": [], "total_requests": 0, "total_endpoints": 0}


def test_inventory_captures_live_traffic_end_to_end(tmp_path, target_app):
    """Requests through a monitored target API (incl. 404s) appear in inventory."""
    db_file = str(tmp_path / "live.db")
    client = TestClient(target_app(db_path=db_file))

    assert client.get("/target/ping").status_code == 200
    assert client.get("/nope/123").status_code == 404

    body = client.get("/api/inventory").json()
    by_key = {(i["method"], i["path"]) for i in body["items"]}
    assert ("GET", "/target/ping") in by_key
    assert ("GET", "/nope/{id}") in by_key
