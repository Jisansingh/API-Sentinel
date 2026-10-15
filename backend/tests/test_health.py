"""Health endpoint tests."""

from fastapi.testclient import TestClient

from app.main import create_app


def test_health_returns_ok(tmp_path):
    app = create_app(db_path=str(tmp_path / "health.db"))
    client = TestClient(app)

    response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["service"] == "api-sentinel"
    assert "version" in body


def test_health_payload_has_no_secrets(tmp_path):
    """The health response must not leak secrets or request details."""
    app = create_app(db_path=str(tmp_path / "health.db"))
    client = TestClient(app)

    body = client.get("/api/health").json()

    forbidden = {"token", "password", "secret", "authorization", "cookie", "body"}
    for key in body:
        assert key.lower() not in forbidden


def test_health_reports_the_api_revision_the_dashboard_checks(tmp_path):
    from app.config import API_REVISION

    body = TestClient(create_app(db_path=str(tmp_path / "health.db"))).get("/api/health").json()
    assert body["api_revision"] == API_REVISION >= 2
