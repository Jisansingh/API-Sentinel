"""GET/POST /api/evaluation: real benchmark results over HTTP, never fabricated.

Runs the actual isolated subprocess against ground-truth-labelled synthetic
scenarios (same mechanism tests/test_phase2_benchmark.py already verifies is
deterministic and never touches a live database). These tests spawn that same
subprocess, so they take a few seconds each.
"""

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.routes import evaluation as ev_module

KEY = "k" * 40
FP = "f" * 40


def _app(tmp_path, **kw):
    return create_app(db_path=str(tmp_path / "eval.db"), api_key=KEY, fp_secret=FP, **kw)


def test_nothing_run_yet_reports_unavailable_not_zeros(tmp_path):
    """available=false, not fabricated zero-value metrics, before any POST."""
    c = TestClient(_app(tmp_path))
    body = c.get("/api/evaluation", headers={"X-Sentinel-Key": KEY}).json()
    assert body["available"] is False
    assert body["overall"] is None and body["scenarios"] == [] and body["per_detection_type"] == {}
    assert "no evaluation has been run yet" in body["note"].lower()


def test_endpoints_require_the_admin_key(tmp_path):
    c = TestClient(_app(tmp_path))
    assert c.get("/api/evaluation").status_code == 401
    assert c.post("/api/evaluation").status_code == 401
    assert c.get("/api/evaluation", headers={"X-Sentinel-Key": "w" * 40}).status_code == 401
    assert c.post("/api/evaluation", headers={"X-Sentinel-Key": "w" * 40}).status_code == 401


def test_post_runs_the_real_benchmark_and_get_returns_the_cached_result(tmp_path):
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    posted = c.post("/api/evaluation")
    assert posted.status_code == 200
    body = posted.json()

    assert body["available"] is True
    assert body["synthetic"] is True
    assert body["seed"] == ev_module.DEFAULT_SEED
    assert body["total_records"] > 0 and body["total_instances"] > 0
    assert body["duration_ms"] > 0
    assert body["ran_at"]

    o = body["overall"]
    assert o["tp"] + o["fp"] + o["tn"] + o["fn"] > 0  # real confusion-matrix counts, not placeholders
    for key in ("precision", "recall", "f1", "false_positive_rate"):
        assert o[key] is None or 0.0 <= o[key] <= 1.0  # "Not measured" (None) or a real ratio

    assert set(body["per_detection_type"]) == {"scraping", "bola_enumeration", "bola", "token_replay"}
    assert len(body["scenarios"]) > 0
    scenario = body["scenarios"][0]
    assert {"name", "description", "holdout", "expected", "instances", "hits", "misses",
            "false_alerts", "detection_rate", "false_alert_rate"} <= set(scenario)
    assert any(s["holdout"] for s in body["scenarios"])       # both splits present
    assert any(not s["holdout"] for s in body["scenarios"])

    shadow = body["shadow_api"]
    assert shadow["spec_loaded"] is True
    assert len(shadow["truth_undocumented"]) >= 2             # matches the benchmark's own known truth set
    assert body["test_execution_coverage"].startswith("not available")

    # GET now returns the same cached result without re-running anything.
    got = c.get("/api/evaluation").json()
    assert got["available"] is True and got["ran_at"] == body["ran_at"] and got["overall"] == o


def test_evaluation_never_touches_the_apps_own_live_database(tmp_path):
    db = tmp_path / "eval.db"
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    before = db.read_bytes()
    c.post("/api/evaluation")
    assert db.read_bytes() == before  # byte-identical: the subprocess never opened this file
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0


def test_timeout_is_reported_generically_not_as_a_raw_traceback(tmp_path, monkeypatch):
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="benchmark.run", timeout=1)
    monkeypatch.setattr(ev_module, "run_benchmark_subprocess", fake_run)
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    r = c.post("/api/evaluation")
    assert r.status_code == 504 and r.json() == {"detail": "evaluation run timed out"}
    assert c.get("/api/evaluation").json()["available"] is False  # nothing cached from a failed run


def test_subprocess_failure_is_reported_generically(tmp_path, monkeypatch):
    def fake_run(*a, **k):
        raise RuntimeError("benchmark run exited 1: /some/internal/path leaked traceback detail")
    monkeypatch.setattr(ev_module, "run_benchmark_subprocess", fake_run)
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    r = c.post("/api/evaluation")
    assert r.status_code == 502 and r.json() == {"detail": "evaluation run failed"}
    assert "/some/internal/path" not in r.text


def test_evaluation_endpoints_are_registered_in_the_rate_limit_listing(tmp_path):
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    items = {i["endpoint"]: i for i in c.get("/api/rate-limits").json()["items"]}
    assert "GET /api/evaluation" in items and "POST /api/evaluation" in items
    assert items["POST /api/evaluation"]["normal_limit"] <= items["GET /api/evaluation"]["normal_limit"]


def test_run_benchmark_subprocess_matches_the_cli_directly(tmp_path):
    """The route's own invocation reproduces exactly what `python -m benchmark.run` gives,
    confirming no detection/scoring logic was duplicated or altered to build this endpoint."""
    direct = json.loads(subprocess.run(
        ["python3", "-m", "benchmark.run", "--seed", str(ev_module.DEFAULT_SEED), "--json", "-"],
        cwd=ev_module.BACKEND_DIR, capture_output=True, text=True, check=True,
    ).stdout)
    via_route = ev_module.run_benchmark_subprocess(ev_module.DEFAULT_SEED)
    direct.pop("timings_not_deterministic"); via_route.pop("timings_not_deterministic")
    assert direct == via_route


# --- persistence across restarts (app/evaluation_store.py) ------------------------------------

import importlib.util  # noqa: E402
import os  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402

from app import evaluation_store  # noqa: E402

DEMO = Path(__file__).resolve().parents[2] / "demo"


@pytest.fixture(scope="module")
def real_raw():
    """One genuine benchmark execution, replayed where a test needs a successful run."""
    return ev_module.run_benchmark_subprocess(ev_module.DEFAULT_SEED)


def _replay(monkeypatch, raw, delay=0.0):
    calls = []

    def fake(seed, timeout=ev_module.RUN_TIMEOUT_SECONDS):
        calls.append(seed)
        time.sleep(delay)
        return json.loads(json.dumps(raw))
    monkeypatch.setattr(ev_module, "run_benchmark_subprocess", fake)
    return calls


def _fail(monkeypatch, exc):
    def fake(*a, **k):
        raise exc
    monkeypatch.setattr(ev_module, "run_benchmark_subprocess", fake)


def test_successful_result_survives_a_new_app_instance(tmp_path, monkeypatch, real_raw):
    _replay(monkeypatch, real_raw)
    first = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY}).post("/api/evaluation").json()
    assert first["persisted"] is True
    stored = tmp_path / evaluation_store.FILE_NAME
    assert stored.exists() and (stored.stat().st_mode & 0o777) == 0o600

    _fail(monkeypatch, AssertionError("GET must not rerun the benchmark"))
    restarted = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})  # fresh app = restart
    got = restarted.get("/api/evaluation").json()
    assert got["available"] is True and got["persisted"] is True
    assert got["ran_at"] == first["ran_at"] and got["overall"] == first["overall"]
    assert got["overall"]["tp"] == real_raw["detection"]["overall"]["tp"]


@pytest.mark.parametrize("exc,status", [
    (RuntimeError("exit 1"), 502), (subprocess.TimeoutExpired("x", 1), 504), (OSError("spawn"), 502)])
def test_failed_run_keeps_the_last_successful_result(tmp_path, monkeypatch, real_raw, exc, status):
    _replay(monkeypatch, real_raw)
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    good = c.post("/api/evaluation").json()
    stored = tmp_path / evaluation_store.FILE_NAME
    before = stored.read_bytes()
    _fail(monkeypatch, exc)
    assert c.post("/api/evaluation").status_code == status
    assert stored.read_bytes() == before
    assert c.get("/api/evaluation").json()["ran_at"] == good["ran_at"]


def test_malformed_benchmark_output_is_rejected_and_not_saved(tmp_path, monkeypatch, real_raw):
    _replay(monkeypatch, real_raw)
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    good = c.post("/api/evaluation").json()
    broken = json.loads(json.dumps(real_raw))
    del broken["detection"]["overall"]
    _replay(monkeypatch, broken)
    r = c.post("/api/evaluation")
    assert r.status_code == 502 and r.json() == {"detail": "evaluation output was malformed"}
    assert c.get("/api/evaluation").json()["ran_at"] == good["ran_at"]


@pytest.mark.parametrize("content,needle", [
    ("", "malformed"), ("{not json", "malformed"), ('{"format": 99, "result": {}}', "unexpected format"),
    ('{"format": 1, "result": {"available": true}}', "failed validation"),
    ('{"format": 1, "result": {"available": false, "note": "x"}}', "incomplete"),
    ('[1, 2]', "unexpected format"),
])
def test_bad_stored_data_is_reported_never_fabricated(tmp_path, content, needle):
    (tmp_path / evaluation_store.FILE_NAME).write_text(content)
    body = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY}).get("/api/evaluation").json()
    assert body["available"] is False and body["overall"] is None and body["scenarios"] == []
    assert needle in body["note"] and "Run a new evaluation" in body["note"]


def test_unreadable_store_is_reported(tmp_path):
    (tmp_path / evaluation_store.FILE_NAME).mkdir()  # a directory where the file should be
    body = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY}).get("/api/evaluation").json()
    assert body["available"] is False and "could not be read" in body["note"]


def test_save_failure_reports_not_persisted_and_keeps_old_file(tmp_path, monkeypatch, real_raw):
    _replay(monkeypatch, real_raw)
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    c.post("/api/evaluation")
    stored = tmp_path / evaluation_store.FILE_NAME
    before = stored.read_bytes()

    def boom(path, result):
        raise PermissionError("read-only")
    monkeypatch.setattr(evaluation_store, "save", boom)
    r = c.post("/api/evaluation").json()
    assert r["available"] is True and r["persisted"] is False and "Not saved" in r["note"]
    assert stored.read_bytes() == before


def test_concurrent_runs_are_refused_not_interleaved(tmp_path, monkeypatch, real_raw):
    calls = _replay(monkeypatch, real_raw, delay=0.6)
    app = _app(tmp_path)
    results = []

    def post():
        results.append(TestClient(app, headers={"X-Sentinel-Key": KEY}).post("/api/evaluation").status_code)
    threads = [threading.Thread(target=post) for _ in range(3)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [200, 409, 409] and len(calls) == 1
    raw = json.loads((tmp_path / evaluation_store.FILE_NAME).read_text())
    assert raw["format"] == evaluation_store.FORMAT_VERSION and raw["result"]["available"] is True


def test_atomic_save_never_exposes_a_partial_file(tmp_path, monkeypatch, real_raw):
    _replay(monkeypatch, real_raw)
    result = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY}).post("/api/evaluation").json()
    path = tmp_path / evaluation_store.FILE_NAME
    from app.schemas import EvaluationResponse
    model = EvaluationResponse.model_validate(result)
    stop, bad = threading.Event(), []

    def writer():
        while not stop.is_set():
            evaluation_store.save(path, model)

    def reader():
        while not stop.is_set():
            loaded, problem = evaluation_store.load(path)
            if loaded is None:
                bad.append(problem)
    ts = [threading.Thread(target=writer), threading.Thread(target=writer), threading.Thread(target=reader)]
    for t in ts:
        t.start()
    time.sleep(1.0)
    stop.set()
    for t in ts:
        t.join()
    assert bad == []
    assert not list(tmp_path.glob(".evaluation-*.tmp"))  # no temp files left behind


def test_store_is_separate_from_the_security_database_and_holds_no_secrets(tmp_path, monkeypatch, real_raw):
    _replay(monkeypatch, real_raw)
    db = tmp_path / "eval.db"
    c = TestClient(_app(tmp_path), headers={"X-Sentinel-Key": KEY})
    before = db.read_bytes()
    c.post("/api/evaluation")
    assert db.read_bytes() == before
    text = (tmp_path / evaluation_store.FILE_NAME).read_text()
    assert KEY not in text and FP not in text
    with pytest.raises(ValueError, match="must not be the security database"):
        create_app(db_path=str(db), api_key=KEY, fp_secret=FP, evaluation_path=str(db))


def test_explicit_location_and_in_memory_database(tmp_path, monkeypatch, real_raw):
    _replay(monkeypatch, real_raw)
    custom = tmp_path / "elsewhere" / "eval-results.json"
    c = TestClient(_app(tmp_path, evaluation_path=str(custom)), headers={"X-Sentinel-Key": KEY})
    assert c.post("/api/evaluation").json()["persisted"] is True and custom.exists()
    assert not (tmp_path / evaluation_store.FILE_NAME).exists()
    mem = TestClient(create_app(db_path=":memory:", api_key=KEY, fp_secret=FP), headers={"X-Sentinel-Key": KEY})
    r = mem.post("/api/evaluation").json()
    assert r["persisted"] is False and "in-memory database" in r["note"]
    assert mem.get("/api/evaluation").json()["available"] is True


def test_proxy_keys_get_and_post_evaluation_only():
    spec = importlib.util.spec_from_file_location("serve_eval", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.KEYED_ROUTES["GET"].match("/api/evaluation")
    assert module.KEYED_ROUTES["POST"].match("/api/evaluation")
    assert not module.KEYED_ROUTES["PATCH"].match("/api/evaluation")
    assert not module.KEYED_ROUTES["POST"].match("/api/evaluation/x")
