"""Request-capture middleware tests (safety-first)."""

from fastapi.testclient import TestClient

from app.capture import REDACTED, sanitize_headers, sanitize_path
from app.main import create_app
from app.storage import count_captured_requests, init_db


def test_sanitize_headers_redacts_secrets():
    headers = {
        "Authorization": "Bearer abc123",
        "Cookie": "session=xyz",
        "X-Api-Key": "key-123",
        "Content-Type": "application/json",
    }

    clean = sanitize_headers(headers)

    assert clean["Authorization"] == REDACTED
    assert clean["Cookie"] == REDACTED
    assert clean["X-Api-Key"] == REDACTED
    assert clean["Content-Type"] == "application/json"  # benign header kept


def test_sanitize_path_redacts_secret_query_params():
    # NOTE: urlencode percent-encodes the brackets in "[REDACTED]" —
    # the value is still redacted, just URL-encoded.
    redacted = sanitize_path("/api/users?token=abc&next=/home")
    assert "abc" not in redacted
    assert "token=" in redacted and "next=" in redacted
    assert "home" in redacted  # benign param value kept
    assert "abc" not in sanitize_path("/api/u?password=hunter2")
    assert sanitize_path("/api/health") == "/api/health"  # no query: unchanged


def test_middleware_captures_safe_summary_only(tmp_path):
    db_file = str(tmp_path / "capture.db")
    init_db(db_file)
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/api/health?token=super-secret&next=/home")

    assert response.status_code == 200
    assert count_captured_requests(db_file) >= 1

    # The DB row must hold the redacted path, never the raw secret.
    import sqlite3

    with sqlite3.connect(db_file) as conn:
        row = conn.execute(
            "SELECT method, path, status_code FROM captured_requests"
            " ORDER BY id DESC LIMIT 1"
        ).fetchone()

    assert row is not None
    method, path, status = row
    assert method == "GET"
    assert status == 200
    assert "super-secret" not in path
    assert "token" in path  # key kept, value redacted


def test_middleware_never_stores_bodies_or_tokens(tmp_path):
    """POSTing a password must not persist the secret anywhere."""
    import sqlite3

    db_file = str(tmp_path / "secrets.db")
    app = create_app(db_path=db_file)
    client = TestClient(app)

    response = client.post(
        "/api/health?access_token=abc123",
        json={"password": "hunter2", "username": "alice"},
    )
    # /api/health only supports GET, so 405 is expected — the point is the
    # capture layer still ran without persisting secrets.
    assert response.status_code in {404, 405}

    with sqlite3.connect(db_file) as conn:
        rows = conn.execute("SELECT method, path FROM captured_requests").fetchall()

    assert rows, "expected at least one captured request"
    blob = " ".join(f"{m} {p}" for m, p in rows)
    assert "hunter2" not in blob
    assert "abc123" not in blob


def test_middleware_disabled_captures_nothing(tmp_path):
    app = create_app(db_path=str(tmp_path / "off.db"), enable_capture=False)
    client = TestClient(app)

    assert client.get("/api/health").status_code == 200
    assert count_captured_requests(str(tmp_path / "off.db")) == 0
