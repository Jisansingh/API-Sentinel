"""Shadow-API endpoint tests (spec comparison + graceful degradation)."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from app.storage import init_db, save_captured_request

FIXTURE_SPEC = Path(__file__).parent / "fixtures" / "sample-openapi.json"


def _seed(db_file: str) -> None:
    init_db(db_file)
    for path in ("/api/health", "/api/users/101", "/api/admin/export"):
        save_captured_request(
            db_file, method="GET", path=path, status_code=200,
            duration_ms=1.0, client_ip="t",
        )


def test_documented_vs_undocumented_routes(tmp_path):
    db_file = str(tmp_path / "shadow.db")
    _seed(db_file)
    client = TestClient(create_app(db_path=db_file, spec_dir=str(FIXTURE_SPEC.parent)))

    response = client.get("/api/shadow-apis", params={"spec_path": str(FIXTURE_SPEC)})

    assert response.status_code == 200
    body = response.json()
    assert body["spec_loaded"] is True
    assert body["spec_error"] is None

    documented = {(r["method"], r["path"]) for r in body["documented"]}
    # /api/users/101 normalizes to /api/users/{id}, matching the spec template.
    # Sentinel's own routes (e.g. /api/health) are hidden even if a row exists.
    assert ("GET", "/api/health") not in documented
    assert ("GET", "/api/users/{id}") in documented

    assert len(body["shadow_apis"]) == 1
    finding = body["shadow_apis"][0]
    assert (finding["method"], finding["path"]) == ("GET", "/api/admin/export")
    assert finding["request_count"] == 1
    assert finding["reason"]  # every shadow finding carries a clear reason


def test_spec_template_with_different_placeholder_name(tmp_path):
    """Spec placeholders need not be literally named 'id' to match."""
    spec = tmp_path / "spec.json"
    spec.write_text(
        '{"openapi": "3.0.0", "info": {"title": "t", "version": "1"},'
        ' "paths": {"/api/users/{userId}": {"get": {"responses": {"200": {}}}}}}'
    )
    db_file = str(tmp_path / "s.db")
    init_db(db_file)
    save_captured_request(
        db_file, method="GET", path="/api/users/999", status_code=200,
        duration_ms=1.0, client_ip="t",
    )
    client = TestClient(create_app(db_path=db_file, spec_dir=str(tmp_path)))

    body = client.get("/api/shadow-apis", params={"spec_path": str(spec)}).json()

    assert body["spec_loaded"] is True
    assert body["documented"] == [{"method": "GET", "path": "/api/users/{id}"}]
    assert body["shadow_apis"] == []


def test_missing_spec_is_handled_gracefully(tmp_path):
    db_file = str(tmp_path / "s.db")
    _seed(db_file)
    client = TestClient(create_app(db_path=db_file, spec_dir=str(tmp_path)))

    response = client.get(
        "/api/shadow-apis",
        params={"spec_path": str(tmp_path / "does-not-exist.json")},
    )

    assert response.status_code == 200  # graceful, not a 500
    body = response.json()
    assert body["spec_loaded"] is False
    assert "not found" in body["spec_error"]
    assert body["documented"] == []
    # Observed routes are surfaced (as unknown-status), never silently dropped.
    assert len(body["shadow_apis"]) == 2  # /api/health is Sentinel's own route: hidden


def test_invalid_spec_is_handled_gracefully(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{ this is not valid JSON")
    db_file = str(tmp_path / "s.db")
    _seed(db_file)
    client = TestClient(create_app(db_path=db_file, spec_dir=str(tmp_path)))

    response = client.get("/api/shadow-apis", params={"spec_path": str(bad)})

    assert response.status_code == 200
    body = response.json()
    assert body["spec_loaded"] is False
    assert "invalid" in body["spec_error"].lower()


def test_no_spec_configured_and_empty_inventory(tmp_path):
    """No spec + no traffic: valid empty response, nothing flagged."""
    db_file = str(tmp_path / "empty.db")
    client = TestClient(create_app(db_path=db_file, spec_dir=str(tmp_path)))

    response = client.get("/api/shadow-apis")

    assert response.status_code == 200
    body = response.json()
    assert body["spec_loaded"] is False
    assert body["documented"] == []
    assert body["shadow_apis"] == []


# --- P1: probe noise is not a shadow API ---------------------------------------

def test_routes_that_only_returned_404_or_405_are_not_shadow_apis(tmp_path):
    db_file = str(tmp_path / "noise.db")
    init_db(db_file)
    for path, status in (
        ("/favicon.ico", 404), ("/login.html", 404), ("/api/health", 405),
        ("/api/admin/export", 200), ("/api/admin/export", 404),
    ):
        save_captured_request(
            db_file, method="GET", path=path, status_code=status,
            duration_ms=1.0, client_ip="t",
        )
    client = TestClient(create_app(db_path=db_file, spec_dir=str(FIXTURE_SPEC.parent)))

    for params in ({"spec_path": str(FIXTURE_SPEC)}, {"spec_path": str(FIXTURE_SPEC.parent / "missing.json")}):
        body = client.get("/api/shadow-apis", params=params).json()
        shadow = {r["path"] for r in body["shadow_apis"]}
        # A route that answered at least once is real; pure 404/405 probes are noise.
        assert "/api/admin/export" in shadow
        assert not shadow & {"/favicon.ico", "/login.html"}
