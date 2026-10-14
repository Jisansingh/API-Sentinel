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


def test_middleware_captures_safe_summary_only(tmp_path, target_app):
    db_file = str(tmp_path / "capture.db")
    init_db(db_file)
    app = target_app(db_path=db_file)
    client = TestClient(app)

    response = client.get("/target/ping?token=super-secret&next=/home")

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


def test_middleware_never_stores_bodies_or_tokens(tmp_path, target_app):
    """POSTing a password must not persist the secret anywhere."""
    import sqlite3

    db_file = str(tmp_path / "secrets.db")
    app = target_app(db_path=db_file)
    client = TestClient(app)

    response = client.post(
        "/target/ping?access_token=abc123",
        json={"password": "hunter2", "username": "alice"},
    )
    # /target/ping only supports GET, so 405 is expected — the point is the
    # capture layer still ran without persisting secrets.
    assert response.status_code in {404, 405}

    with sqlite3.connect(db_file) as conn:
        rows = conn.execute("SELECT method, path FROM captured_requests").fetchall()

    assert rows, "expected at least one captured request"
    blob = " ".join(f"{m} {p}" for m, p in rows)
    assert "hunter2" not in blob
    assert "abc123" not in blob


def test_middleware_disabled_captures_nothing(tmp_path, target_app):
    app = target_app(db_path=str(tmp_path / "off.db"), enable_capture=False)
    client = TestClient(app)

    assert client.get("/target/ping").status_code == 200
    assert count_captured_requests(str(tmp_path / "off.db")) == 0


# --- P1: self-traffic exclusion + credential fingerprints ---------------------

import sqlite3 as _sqlite3

from app.capture import credential_fingerprint, is_self_route
from app.storage import fetch_captured_requests

FP_SECRET = "s" * 32


def test_sentinel_own_routes_are_not_captured(tmp_path, target_app):
    """Health checks and dashboard polling must not become 'traffic'."""
    db_file = str(tmp_path / "self.db")
    client = TestClient(target_app(db_path=db_file))
    for route in (
        "/api/health", "/api/inventory", "/api/findings", "/api/shadow-apis",
        "/api/alerts", "/docs", "/openapi.json",
    ):
        client.get(route)
    for _ in range(20):  # a health-check monitor polling every few seconds
        client.get("/api/health")
    assert count_captured_requests(db_file) == 0
    client.get("/target/ping")  # monitored traffic is still captured
    assert count_captured_requests(db_file) == 1
    assert client.get("/api/findings").json()["total_findings"] == 0


def test_is_self_route_matches_whole_segments_only():
    assert is_self_route("/api/alerts/7")
    assert is_self_route("/api/health")
    assert not is_self_route("/api/alertsx")
    assert not is_self_route("/api/healthz")
    assert not is_self_route("/target/ping")


def test_credential_fingerprint_is_keyed_and_stable():
    fp = credential_fingerprint({"authorization": "Bearer abc"}, FP_SECRET.encode())
    assert fp and "abc" not in fp and len(fp) == 32
    assert fp == credential_fingerprint({"authorization": "Bearer abc"}, FP_SECRET.encode())
    assert fp != credential_fingerprint({"authorization": "Bearer abc"}, b"t" * 32)
    assert credential_fingerprint({"x-api-key": "k"}, FP_SECRET.encode())
    assert credential_fingerprint({"authorization": "Bearer abc"}, None) is None
    assert credential_fingerprint({}, FP_SECRET.encode()) is None


def test_middleware_stores_fingerprint_never_raw_credentials(tmp_path, target_app):
    db_file = str(tmp_path / "fp.db")
    client = TestClient(target_app(db_path=db_file, fp_secret=FP_SECRET))
    client.get("/target/ping", headers={"Authorization": "Bearer raw-token-123"})
    client.get("/target/ping", headers={"X-API-Key": "raw-key-456"})
    client.get("/target/ping")  # anonymous -> IP fallback (no fingerprint)

    rows = fetch_captured_requests(db_file)
    assert [bool(r["actor_fp"]) for r in rows] == [True, True, False]
    assert rows[0]["actor_fp"] != rows[1]["actor_fp"]
    with _sqlite3.connect(db_file) as conn:
        dump = "\n".join(conn.iterdump())
    assert "raw-token-123" not in dump and "raw-key-456" not in dump
    assert FP_SECRET not in dump


def test_short_or_missing_secret_disables_fingerprinting(tmp_path, target_app):
    for secret in (None, "too-short"):
        db_file = str(tmp_path / f"nofp-{bool(secret)}.db")
        client = TestClient(target_app(db_path=db_file, fp_secret=secret))
        client.get("/target/ping", headers={"Authorization": "Bearer x"})
        assert fetch_captured_requests(db_file)[0]["actor_fp"] is None


def test_init_db_adds_actor_fp_to_existing_database(tmp_path):
    """Additive migration: an old-schema DB keeps its rows and gains the column."""
    db_file = str(tmp_path / "old.db")
    with _sqlite3.connect(db_file) as conn:
        conn.execute(
            "CREATE TABLE captured_requests (id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " method TEXT NOT NULL, path TEXT NOT NULL, status_code INTEGER NOT NULL,"
            " duration_ms REAL NOT NULL, client_ip TEXT NOT NULL DEFAULT '',"
            " created_at TEXT NOT NULL DEFAULT (datetime('now')))"
        )
        conn.execute(
            "INSERT INTO captured_requests (method, path, status_code, duration_ms)"
            " VALUES ('GET', '/old', 200, 1.0)"
        )
    init_db(db_file)
    init_db(db_file)  # idempotent
    rows = fetch_captured_requests(db_file)
    assert rows[0]["path"] == "/old" and rows[0]["actor_fp"] is None
