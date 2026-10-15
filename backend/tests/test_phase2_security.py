"""Phase 2 security hardening: spec-path confinement, safe errors, production
fail-closed, loopback default, lazy app, health, access-log redaction."""

import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.config import Settings, get_settings
from app.main import RedactQueryFilter, create_app
from app.storage import init_db, save_captured_request

BACKEND = Path(__file__).resolve().parents[1]
KEY = "k" * 32
FP = "f" * 32
SPEC = '{"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {"/api/a": {"get": {}}}}'


def _client(tmp_path, spec_dir=None, **kw):
    db = str(tmp_path / "s.db")
    init_db(db)
    save_captured_request(db, method="GET", path="/api/a", status_code=200, duration_ms=1.0, client_ip="t")
    return TestClient(create_app(db_path=db, spec_dir=str(spec_dir) if spec_dir else None, **kw))


# --- spec_path confinement ----------------------------------------------------

def test_spec_inside_allowed_dir_is_read(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "ok.json").write_text(SPEC)
    r = _client(tmp_path, specs).get("/api/shadow-apis", params={"spec_path": str(specs / "ok.json")})
    assert r.status_code == 200 and r.json()["spec_loaded"] is True


@pytest.mark.parametrize("make", [
    lambda specs, outside: str(specs / ".." / "outside.json"),  # traversal
    lambda specs, outside: str(outside),                          # absolute, elsewhere
    lambda specs, outside: "/etc/passwd",                         # sensitive file
    lambda specs, outside: str(specs / "link.json"),              # symlink escape
    lambda specs, outside: str(specs / "notes.txt"),              # wrong extension
])
def test_spec_outside_allowed_dir_or_wrong_type_is_rejected(tmp_path, make):
    specs = tmp_path / "specs"
    specs.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text(SPEC)
    link = specs / "link.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        if "link.json" in make.__code__.co_consts:
            pytest.skip("symlink creation requires Windows Developer Mode or elevated privileges")
    (specs / "notes.txt").write_text(SPEC)
    r = _client(tmp_path, specs).get("/api/shadow-apis", params={"spec_path": make(specs, outside)})
    assert r.status_code == 400
    assert str(tmp_path) not in r.text and "passwd" not in r.text


def test_spec_override_is_disabled_without_any_allowed_dir(tmp_path):
    spec = tmp_path / "x.json"
    spec.write_text(SPEC)
    assert _client(tmp_path).get("/api/shadow-apis", params={"spec_path": str(spec)}).status_code == 400


def test_configured_spec_directory_is_allowed(tmp_path, monkeypatch):
    spec = tmp_path / "configured.json"
    other = tmp_path / "other.json"
    spec.write_text(SPEC)
    other.write_text(SPEC)
    monkeypatch.setenv("OPENAPI_SPEC_PATH", str(spec))
    get_settings.cache_clear()
    try:
        client = _client(tmp_path)
        assert client.get("/api/shadow-apis").json()["spec_loaded"] is True
        r = client.get("/api/shadow-apis", params={"spec_path": str(other)})
        assert r.status_code == 200  # sibling of the operator-configured spec
    finally:
        monkeypatch.undo()
        get_settings.cache_clear()


def test_spec_errors_never_disclose_paths_or_content(tmp_path):
    (tmp_path / "bad.json").write_text("{ SECRET-CONTENT not json")
    (tmp_path / "huge.json").write_text(SPEC + " " * (2 * 1024 * 1024))
    client = _client(tmp_path, tmp_path)
    for name in ("missing.json", "bad.json", "huge.json"):
        body = client.get("/api/shadow-apis", params={"spec_path": str(tmp_path / name)}).json()
        assert body["spec_loaded"] is False
        assert str(tmp_path) not in body["spec_error"] and "SECRET" not in body["spec_error"]
    assert "too large" in client.get(
        "/api/shadow-apis", params={"spec_path": str(tmp_path / "huge.json")}).json()["spec_error"]


# --- production fails closed ---------------------------------------------------

def test_production_requires_key_and_fp_secret_and_no_demo(tmp_path):
    db = str(tmp_path / "p.db")
    with pytest.raises(ValueError, match="SENTINEL_API_KEY"):
        create_app(db_path=db, env="production", fp_secret=FP)
    with pytest.raises(ValueError, match="SENTINEL_FP_SECRET"):
        create_app(db_path=db, env="production", api_key=KEY)
    with pytest.raises(ValueError, match="ENABLE_DEMO_TARGET"):
        create_app(db_path=db, env="production", api_key=KEY, fp_secret=FP, enable_demo=True)
    with pytest.raises(ValueError, match="SENTINEL_ENV"):
        create_app(db_path=db, env="staging")
    app = create_app(db_path=db, env="production", api_key=KEY, fp_secret=FP, enable_demo=False)
    assert TestClient(app).get("/api/inventory").status_code == 401  # reads need the key


def test_development_still_boots_open_for_the_local_demo(tmp_path):
    client = TestClient(create_app(db_path=str(tmp_path / "d.db")))
    assert client.get("/api/inventory").status_code == 200
    assert client.post("/api/scan").status_code == 503  # writes stay disabled without a key


def test_default_bind_is_loopback():
    assert Settings().api_host == "127.0.0.1"


# --- importing the module must not create a database -----------------------------

def test_import_does_not_create_a_database(tmp_path):
    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
    env.update(DATABASE_URL="sqlite:///./import_check.db", PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=str(BACKEND))
    subprocess.run([sys.executable, "-c", "import app.main"], cwd=tmp_path, env=env, check=True)
    assert not (tmp_path / "import_check.db").exists()
    subprocess.run([sys.executable, "-c", "import app.main as m; m.app"], cwd=tmp_path, env=env, check=True)
    assert (tmp_path / "import_check.db").exists()  # uvicorn app.main:app still works


# --- health ---------------------------------------------------------------------

def test_health_reports_database_state_without_creating_it(tmp_path):
    db = tmp_path / "h.db"
    client = TestClient(create_app(db_path=str(db)))
    assert client.get("/api/health").json()["database"] == "ok"
    db.unlink()
    r = client.get("/api/health")
    assert r.status_code == 503
    assert r.json()["status"] == "degraded" and str(tmp_path) not in r.text
    assert not db.exists()  # the probe must not recreate it


# --- access-log redaction ---------------------------------------------------------

def test_access_log_filter_redacts_secret_query_values():
    record = logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                               '%s - "%s %s HTTP/%s" %d',
                               ("1.2.3.4:5", "GET", "/x?token=abc123&page=2", "1.1", 200), None)
    assert RedactQueryFilter().filter(record)
    line = record.getMessage()
    assert "abc123" not in line and "page=2" in line


def test_create_app_installs_the_filter_once(tmp_path):
    create_app(db_path=str(tmp_path / "a.db"))
    create_app(db_path=str(tmp_path / "b.db"))
    filters = [f for f in logging.getLogger("uvicorn.access").filters if isinstance(f, RedactQueryFilter)]
    assert len(filters) == 1
