"""Findings endpoint tests (integration pipeline: capture -> detectors -> findings)."""

from fastapi.testclient import TestClient

from app.main import create_app
from app.risk_scoring import RiskScorer
from app.storage import init_db, save_captured_request


def _seed_volume(db_file: str, n: int = 15, ip: str = "testclient") -> None:
    init_db(db_file)
    for i in range(n):
        save_captured_request(
            db_file,
            method="GET",
            path=f"/api/items/{i}",
            status_code=200,
            duration_ms=1.0,
            client_ip=ip,
        )


def test_empty_database_returns_empty_findings(tmp_path):
    db_file = str(tmp_path / "empty.db")
    client = TestClient(create_app(db_path=db_file))

    response = client.get("/api/findings")

    assert response.status_code == 200
    body = response.json()
    assert body == {"items": [], "total_findings": 0}


def test_normal_traffic_triggers_no_alerts(tmp_path):
    db_file = str(tmp_path / "normal.db")
    init_db(db_file)
    for i in range(3):
        save_captured_request(
            db_file, method="GET", path=f"/api/items/{i}",
            status_code=200, duration_ms=1.0, client_ip="testclient",
        )
    client = TestClient(create_app(db_path=db_file))

    body = client.get("/api/findings").json()

    assert body["items"] == []
    assert body["total_findings"] == 0


def test_live_normal_traffic_triggers_no_alerts(tmp_path):
    """A few requests against our own demo API must stay quiet."""
    db_file = str(tmp_path / "live-normal.db")
    client = TestClient(create_app(db_path=db_file))

    for _ in range(3):
        assert client.get("/api/health").status_code == 200

    body = client.get("/api/findings").json()
    assert body["items"] == []
    assert body["total_findings"] == 0


def test_high_volume_traffic_produces_scraping_finding(tmp_path):
    _seed_volume(str(tmp_path / "vol.db"), n=15)
    client = TestClient(create_app(db_path=str(tmp_path / "vol.db")))

    response = client.get("/api/findings")

    assert response.status_code == 200
    body = response.json()
    assert body["total_findings"] == 1
    finding = body["items"][0]
    # Required finding shape.
    assert finding["detection_type"] == "scraping"
    assert finding["endpoint"]  # affected endpoint/resource
    assert 0 <= finding["risk_score"] <= 100
    assert finding["reason"]  # human-readable
    assert finding["timestamp"]  # timestamp present
    assert isinstance(finding["metadata"], dict)
    # Single-signal score: exactly the scraping weight, no double-counting.
    assert finding["risk_score"] == RiskScorer.SCRAPING_WEIGHT
    assert finding["metadata"]["breakdown"]["scraping"] == RiskScorer.SCRAPING_WEIGHT
    assert finding["metadata"]["breakdown"]["bola"] == 0
    assert finding["metadata"]["breakdown"]["token_replay"] == 0


def test_end_to_end_live_capture_to_findings(tmp_path):
    """Full flow: HTTP traffic -> capture -> scraping finding."""
    db_file = str(tmp_path / "e2e.db")
    client = TestClient(create_app(db_path=db_file))

    for i in range(15):
        assert client.get(f"/api/health?n={i}").status_code == 200

    body = client.get("/api/findings").json()

    assert body["total_findings"] >= 1
    finding = body["items"][0]
    assert finding["detection_type"] == "scraping"
    assert 0 <= finding["risk_score"] <= 100
    assert finding["reason"]
    assert finding["timestamp"]


def test_findings_are_deterministic(tmp_path):
    _seed_volume(str(tmp_path / "det.db"), n=15)
    client = TestClient(create_app(db_path=str(tmp_path / "det.db")))

    first = client.get("/api/findings").json()
    # The first /api/findings call is itself captured, so the second call
    # analyzes one extra record and its count-based reason may grow. Type,
    # endpoint, and single-signal risk score must stay stable.
    second = client.get("/api/findings").json()

    assert first["items"][0]["detection_type"] == second["items"][0]["detection_type"]
    assert first["items"][0]["endpoint"] == second["items"][0]["endpoint"]
    assert first["items"][0]["risk_score"] == second["items"][0]["risk_score"]
    assert first["total_findings"] == second["total_findings"] == 1


def test_configurable_thresholds_are_respected(tmp_path):
    _seed_volume(str(tmp_path / "thr.db"), n=15)
    client = TestClient(create_app(db_path=str(tmp_path / "thr.db")))

    body = client.get(
        "/api/findings",
        params={"rate_threshold": 1000, "distinct_threshold": 1000},
    ).json()

    assert body["items"] == []
    assert body["total_findings"] == 0


def test_findings_never_expose_secrets(tmp_path):
    db_file = str(tmp_path / "secrets.db")
    init_db(db_file)
    save_captured_request(
        db_file, method="GET", path="/api/u?token=%5BREDACTED%5D&next=/x",
        status_code=200, duration_ms=1.0, client_ip="t",
    )
    for i in range(14):
        save_captured_request(
            db_file, method="GET", path=f"/api/items/{i}",
            status_code=200, duration_ms=1.0, client_ip="t",
        )
    client = TestClient(create_app(db_path=db_file))

    blob = client.get("/api/findings").text

    assert "hunter2" not in blob
    assert "super-secret" not in blob
    assert "abc123" not in blob
