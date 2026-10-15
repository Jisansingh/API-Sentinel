"""P3: persistent, deduplicated alerts (POST /api/scan, GET/PATCH /api/alerts)."""

import sqlite3
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.main import create_app
from app.storage import init_db

T0 = datetime(2026, 10, 14, 0, 0, 0)
API_KEY = "a" * 32
AUTH = {"X-Sentinel-Key": API_KEY}


def _insert(db_file, n, start=T0, ip="1.2.3.4", path="/api/items/{i}", status=200, fp=None):
    init_db(db_file)
    with sqlite3.connect(db_file) as conn:
        for i in range(n):
            conn.execute(
                "INSERT INTO captured_requests (method, path, status_code, duration_ms,"
                " client_ip, created_at, actor_fp) VALUES ('GET', ?, ?, 1.0, ?, ?, ?)",
                (path.format(i=i), status, ip,
                 (start + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S"), fp),
            )


def _client(db_file):
    return TestClient(create_app(db_path=db_file, api_key=API_KEY), headers=AUTH)


def test_no_alerts_until_scan_and_get_never_scans(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    client = _client(db_file)
    assert client.get("/api/alerts").json() == {"items": [], "total": 0}
    client.get("/api/findings")  # read-only too: must not create alerts
    assert client.get("/api/alerts").json()["total"] == 0


def test_scan_creates_one_open_alert_with_required_fields(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    client = _client(db_file)

    scan = client.post("/api/scan")
    assert scan.status_code == 200
    assert scan.json() == {"findings": 1, "created": 1, "updated": 0, "unchanged": 0}

    alert = client.get("/api/alerts").json()["items"][0]
    assert alert["detection_type"] == "scraping"
    assert alert["actor"] == "1.2.3.4"
    assert alert["endpoint"] == "/api/items/{id}"
    assert alert["status"] == "open"
    assert alert["occurrences"] == 1
    assert alert["first_seen"] == alert["last_seen"]
    assert 0 < alert["risk_score"] <= 100
    assert alert["reason"] and isinstance(alert["metadata"], dict)


def test_rescanning_same_evidence_is_idempotent(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    client = _client(db_file)
    client.post("/api/scan")
    assert client.post("/api/scan").json() == {
        "findings": 1, "created": 0, "updated": 0, "unchanged": 1,
    }
    items = client.get("/api/alerts").json()["items"]
    assert len(items) == 1 and items[0]["occurrences"] == 1


def test_alert_persists_after_burst_leaves_window_and_restart(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    _client(db_file).post("/api/scan")
    # Same actor, quiet traffic later: the rolling finding disappears...
    _insert(db_file, 2, start=T0 + timedelta(minutes=10), path="/target/ping")
    client = _client(db_file)  # ...a fresh app instance (restart) on the same DB
    assert client.get("/api/findings").json()["total_findings"] == 0
    client.post("/api/scan")
    items = client.get("/api/alerts").json()["items"]
    assert [a["detection_type"] for a in items] == ["scraping"]  # ...but the alert stays


def test_new_evidence_updates_and_reopens_resolved_alert(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    client = _client(db_file)
    client.post("/api/scan")
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]
    patched = client.patch(f"/api/alerts/{alert_id}", json={"status": "resolved", "note": "blocked IP"})
    assert patched.status_code == 200
    assert patched.json()["status"] == "resolved" and patched.json()["note"] == "blocked IP"

    _insert(db_file, 15, start=T0 + timedelta(minutes=10))
    assert client.post("/api/scan").json()["updated"] == 1
    alert = client.get("/api/alerts").json()["items"][0]
    assert alert["status"] == "open"
    assert alert["occurrences"] == 2
    assert alert["last_seen"] > alert["first_seen"]


def test_ignored_alert_stays_ignored_on_new_evidence(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    client = _client(db_file)
    client.post("/api/scan")
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]
    client.patch(f"/api/alerts/{alert_id}", json={"status": "ignored"})
    _insert(db_file, 15, start=T0 + timedelta(minutes=10))
    client.post("/api/scan")
    alert = client.get("/api/alerts").json()["items"][0]
    assert alert["status"] == "ignored" and alert["occurrences"] == 2
    assert client.get("/api/alerts", params={"status": "open"}).json()["total"] == 0
    assert client.get("/api/alerts", params={"status": "ignored"}).json()["total"] == 1


def test_distinct_actors_get_distinct_alerts(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15, ip="1.1.1.1")
    _insert(db_file, 15, ip="2.2.2.2")
    client = _client(db_file)
    assert client.post("/api/scan").json()["created"] == 2


def test_patch_validation(tmp_path):
    db_file = str(tmp_path / "a.db")
    _insert(db_file, 15)
    client = _client(db_file)
    client.post("/api/scan")
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "deleted"}).status_code == 422
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "open", "note": "x" * 501}).status_code == 422
    assert client.patch("/api/alerts/999", json={"status": "resolved"}).status_code == 404
    assert client.get("/api/alerts", params={"status": "bogus"}).status_code == 422


def test_alerts_never_contain_raw_credentials(tmp_path, target_app):
    db_file = str(tmp_path / "a.db")
    app = target_app(db_path=db_file, fp_secret="k" * 32, api_key=API_KEY)
    for i in range(5):
        TestClient(app, client=(f"10.0.0.{i}", 5000)).get(
            "/target/ping", headers={"Authorization": "Bearer stolen-token"}
        )
    client = TestClient(app, headers=AUTH)
    assert client.post("/api/scan").json()["created"] == 1
    body = client.get("/api/alerts").json()
    assert body["items"][0]["detection_type"] == "token_replay"
    with sqlite3.connect(db_file) as conn:
        dump = "\n".join(conn.iterdump())
    assert "stolen-token" not in dump and "stolen-token" not in str(body)


# --- Regression: a burst nobody scanned while it was "current" ------------------

def test_burst_that_left_rolling_window_before_any_scan_still_alerts(tmp_path):
    """Scan must not depend on catching the burst while it is the latest window."""
    db_file = str(tmp_path / "late.db")
    _insert(db_file, 15)  # scraping burst at T0 ... T0+14s
    _insert(db_file, 3, start=T0 + timedelta(minutes=10), path="/target/ping")  # quiet later
    client = _client(db_file)
    # Rolling findings (current state) no longer show the burst...
    assert client.get("/api/findings").json()["total_findings"] == 0
    # ...but the first-ever scan still records it, stamped at the burst's end.
    assert client.post("/api/scan").json()["created"] == 1
    alert = client.get("/api/alerts").json()["items"][0]
    assert alert["detection_type"] == "scraping"
    assert alert["endpoint"] == "/api/items/{id}"
    assert alert["last_seen"] == (T0 + timedelta(seconds=14)).isoformat()
    assert alert["metadata"]["request_count"] == 15
    # Re-scanning the same history is idempotent.
    assert client.post("/api/scan").json()["unchanged"] == 1
