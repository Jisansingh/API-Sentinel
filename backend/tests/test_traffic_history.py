"""Persistent real-traffic history and adaptive baselines (app/traffic_history.py)."""

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app
from app.maintenance import prune
from app.storage import init_db, save_captured_request, upsert_alerts
from app.traffic_history import MIN_BUCKETS, MIN_DAYS, MIN_SPAN_HOURS, evaluate

KEY = "k" * 40
FP = "f" * 40
NOW = datetime(2026, 10, 16, 12, 30, 0)
DEMO = Path(__file__).resolve().parents[2] / "demo"


def _save(db, path, at, *, status=200, n=1, fp=None, ip="10.0.0.1", size=None):
    for _ in range(n):
        save_captured_request(db, method="GET", path=path, status_code=status, duration_ms=1, client_ip=ip,
                              actor_fp=fp, created_at=at.strftime("%Y-%m-%d %H:%M:%S"), response_bytes=size)


def _db(tmp_path, name="h.db"):
    db = str(tmp_path / name)
    init_db(db)
    return db


def _eval(db, persist=False, alerts=None, now=NOW):
    with sqlite3.connect(db) as conn:
        out = evaluate(conn, alerts or [], now=now, persist=persist)
        conn.commit()
    return {(e["method"], e["endpoint"]): e for e in out["endpoints"]}


def _slow_history(db, path="/api/items/1", days=4, per_hour=3, hours=(9, 10, 11, 12)):
    """Sparse, steady traffic over several days (never one burst)."""
    for d in range(days, 0, -1):
        for h in hours:
            _save(db, path, NOW.replace(hour=h, minute=5) - timedelta(days=d), n=per_hour)


# --- capture -> history: privacy, persistence, isolation -------------------------------------------

def _rows(db, table):
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(f"SELECT * FROM {table}")]


def test_real_requests_are_recorded_without_secrets_and_survive_a_restart(tmp_path):
    db = str(tmp_path / "live.db")
    app = create_app(db_path=db, api_key=KEY, fp_secret=FP, enable_demo=True, clock=lambda: NOW)
    shop = TestClient(app)
    shop.get("/shop/products/7?token=SECRET-QUERY&page=2", headers={"Cookie": "session=SECRET-COOKIE"})
    shop.get("/shop/me", headers={"Authorization": "Bearer demo-alice-token"})
    shop.get("/shop/products/8")
    TestClient(app, headers={"X-Sentinel-Key": KEY}).get("/api/inventory")  # Sentinel's own route: not history
    blob = json.dumps([_rows(db, "traffic_history"), _rows(db, "traffic_history_callers")])
    for secret in ("SECRET-QUERY", "SECRET-COOKIE", "demo-alice-token", "token=", "page=", KEY):
        assert secret not in blob
    hist = {(r["method"], r["endpoint"]): r for r in _rows(db, "traffic_history")}
    assert set(hist) == {("GET", "/shop/products/{id}"), ("GET", "/shop/me")}
    assert hist[("GET", "/shop/products/{id}")]["requests"] == 2 and hist[("GET", "/shop/products/{id}")]["status_2xx"] == 2
    assert hist[("GET", "/shop/products/{id}")]["response_sized"] == 2 and hist[("GET", "/shop/products/{id}")]["response_bytes_max"] > 0
    callers = {r["caller"] for r in _rows(db, "traffic_history_callers")}
    assert any(c.startswith("credential:") and len(c) == len("credential:") + 32 for c in callers)

    restarted = create_app(db_path=db, api_key=KEY, fp_secret=FP, clock=lambda: NOW)  # same file, new process state
    body = TestClient(restarted, headers={"X-Sentinel-Key": KEY}).get("/api/runtime/history").json()
    assert {(e["method"], e["endpoint"]): e["observations"] for e in body["endpoints"]} == {
        ("GET", "/shop/products/{id}"): 2, ("GET", "/shop/me"): 1}
    assert "not synthetic benchmark" in body["source"]


def test_history_matches_captures_one_for_one(tmp_path):
    db = _db(tmp_path)
    _save(db, "/a/1", NOW, n=5)
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()[0] == 5
        assert conn.execute("SELECT SUM(requests) FROM traffic_history").fetchone()[0] == 5


def test_main_and_lab_databases_stay_separate(tmp_path):
    main = create_app(db_path=str(tmp_path / "main.db"), api_key=KEY, enable_demo=True)
    lab = create_app(db_path=str(tmp_path / "lab.db"), api_key=KEY, enable_demo=True)
    TestClient(main).get("/shop/products/1")
    assert _rows(str(tmp_path / "lab.db"), "traffic_history") == []
    assert len(_rows(str(tmp_path / "main.db"), "traffic_history")) == 1
    assert lab.state.db_path != main.state.db_path


# --- baseline states and their evidence requirements -----------------------------------------------

def test_first_traffic_has_no_baseline(tmp_path):
    db = _db(tmp_path)
    _save(db, "/api/items/1", NOW, n=3)
    (e,) = _eval(db).values()
    assert e["state"] == "no_baseline" and e["confidence"] == "none" and e["baseline"] is None


def test_a_single_burst_is_never_ready(tmp_path):
    db = _db(tmp_path)
    _save(db, "/api/items/1", NOW - timedelta(hours=3), n=500)
    (e,) = _eval(db, persist=True).values()
    assert e["state"] == "insufficient" and len(e["unmet_requirements"]) == 3
    assert f"1 of {MIN_DAYS} required days" in e["unmet_requirements"][0]
    assert _rows(db, "endpoint_baselines") == []  # nothing trusted was stored


def test_slow_traffic_across_days_becomes_ready_then_detects_a_deviation(tmp_path):
    db = _db(tmp_path)
    _slow_history(db)
    (e,) = _eval(db).values()
    assert e["state"] == "ready" and e["evidence"]["days"] >= MIN_DAYS
    assert e["evidence"]["span_hours"] >= MIN_SPAN_HOURS and e["evidence"]["active_hours"] >= MIN_BUCKETS
    assert e["baseline"]["median_requests_per_active_hour"] == 3 and "same hour of day" in e["explanation"]
    _save(db, "/api/items/1", NOW, n=3)
    assert _eval(db)[("GET", "/api/items/{id}")]["state"] == "ready"
    _save(db, "/api/items/1", NOW, n=60)
    dev = _eval(db)[("GET", "/api/items/{id}")]
    assert dev["state"] == "deviation" and "exceed the threshold" in dev["explanation"]


def test_server_errors_and_large_responses_are_deviations(tmp_path):
    db = _db(tmp_path)
    _slow_history(db, per_hour=10)
    _save(db, "/api/items/1", NOW, n=2, status=503)
    _save(db, "/api/items/1", NOW, n=8, status=503)
    e = _eval(db)[("GET", "/api/items/{id}")]
    assert e["state"] == "deviation" and "5xx share 100%" in e["explanation"]
    db2 = _db(tmp_path, "s.db")
    for d in range(4, 0, -1):
        for h in (9, 10, 11, 12):
            _save(db2, "/api/files/1", NOW.replace(hour=h) - timedelta(days=d), n=3, size=1000)
    _save(db2, "/api/files/1", NOW, n=2, size=900_000)
    e = _eval(db2)[("GET", "/api/files/{id}")]
    assert e["state"] == "deviation" and "largest response 900000 bytes" in e["explanation"]


# --- poisoning: suspicious hours are quarantined, trusted baselines kept ------------------------------

def test_a_burst_after_learning_is_quarantined_and_not_learned(tmp_path):
    db = _db(tmp_path)
    _slow_history(db)
    learned = _eval(db, persist=True)[("GET", "/api/items/{id}")]["baseline"]
    _save(db, "/api/items/1", NOW.replace(hour=11, minute=0) - timedelta(days=1), n=400)  # poison attempt yesterday
    after = _eval(db, persist=True)[("GET", "/api/items/{id}")]
    assert after["quarantined_hours"] == 1 and "exceeded the trusted baseline" in after["explanation"]
    assert after["baseline"]["median_requests_per_active_hour"] == learned["median_requests_per_active_hour"]
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT quarantined FROM traffic_history WHERE requests = 403").fetchone() == (1,)


def test_hours_overlapping_an_alert_are_not_learned_unless_the_alert_was_ignored(tmp_path):
    db = _db(tmp_path)
    _slow_history(db)
    hour = (NOW - timedelta(days=2)).replace(hour=10, minute=5)
    alert = {"detection_type": "scraping", "actor": "10.0.0.1", "endpoint": "/api/items/{id}", "risk_score": 40,
             "reason": "r", "timestamp": hour.isoformat(), "metadata": {"method": "GET", "first_seen": hour.isoformat()}}
    upsert_alerts(db, [alert])
    with sqlite3.connect(db) as conn:
        conn.row_factory = sqlite3.Row
        stored = [dict(r, metadata=json.loads(r["metadata"])) for r in conn.execute("SELECT * FROM alerts")]
    e = _eval(db, alerts=stored)[("GET", "/api/items/{id}")]
    assert e["quarantined_hours"] == 1 and "overlaps alert #1 (scraping)" in e["explanation"]
    ignored = [{**stored[0], "status": "ignored"}]
    assert _eval(db, alerts=ignored)[("GET", "/api/items/{id}")]["quarantined_hours"] == 0


def test_last_trusted_baseline_is_kept_when_evidence_lapses(tmp_path):
    db = _db(tmp_path)
    _slow_history(db)
    _eval(db, persist=True)
    with sqlite3.connect(db) as conn:  # simulate retention removing most history
        conn.execute("DELETE FROM traffic_history WHERE bucket_start < ?", ((NOW - timedelta(days=1)).isoformat(),))
        conn.commit()
    e = _eval(db, persist=True)[("GET", "/api/items/{id}")]  # still listed although its history is gone
    assert e["state"] == "ready" and "Using the last trusted baseline" in e["explanation"]
    assert e["unmet_requirements"] and e["observations"] == 0 and e["first_seen"] is None
    assert len(_rows(db, "endpoint_baselines")) == 1


# --- API, scan, migration, retention ----------------------------------------------------------------

def test_reading_history_never_writes_and_scanning_learns(tmp_path):
    db = _db(tmp_path)
    _slow_history(db)
    app = create_app(db_path=db, api_key=KEY, clock=lambda: NOW)
    admin = TestClient(app, headers={"X-Sentinel-Key": KEY})
    before = hashlib.sha256(Path(db).read_bytes()).hexdigest()
    assert admin.get("/api/runtime/history").json()["endpoints"][0]["state"] == "ready"
    assert hashlib.sha256(Path(db).read_bytes()).hexdigest() == before
    assert TestClient(app).get("/api/runtime/history").status_code == 401
    admin.post("/api/scan")
    assert len(_rows(db, "endpoint_baselines")) == 1


def test_existing_captures_are_backfilled_once_and_left_untouched(tmp_path):
    db = str(tmp_path / "old.db")
    with sqlite3.connect(db) as conn:  # a database from before traffic history existed
        conn.execute("CREATE TABLE captured_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, method TEXT NOT NULL,"
                     " path TEXT NOT NULL, status_code INTEGER NOT NULL, duration_ms REAL NOT NULL, client_ip TEXT NOT NULL"
                     " DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), actor_fp TEXT)")
        for i in range(4):
            conn.execute("INSERT INTO captured_requests (method, path, status_code, duration_ms, client_ip, created_at)"
                         " VALUES ('GET', ?, 200, 1, '1.2.3.4', '2026-10-15 09:10:00')", (f"/a/{i}",))
        conn.execute("INSERT INTO captured_requests (method, path, status_code, duration_ms, client_ip, created_at)"
                     " VALUES ('GET', '/api/inventory', 200, 1, '1.2.3.4', '2026-10-15 09:10:00')")
    before = _rows(db, "captured_requests")
    init_db(db)
    init_db(db)  # idempotent: no double counting
    (h,) = _rows(db, "traffic_history")
    assert (h["endpoint"], h["requests"], h["response_sized"]) == ("/a/{id}", 4, 0)  # internal route skipped
    assert [{k: r[k] for k in before[0]} for r in _rows(db, "captured_requests")] == before


def test_retention_prunes_old_history_only_with_apply(tmp_path):
    db = _db(tmp_path)
    _save(db, "/a/1", datetime(2020, 1, 1, 9))
    _save(db, "/a/1", datetime.now().replace(microsecond=0) - timedelta(hours=1))
    assert prune(db, history_days=30)["history_hours_deleted"] == 1 and len(_rows(db, "traffic_history")) == 2
    prune(db, history_days=30, apply=True)
    assert len(_rows(db, "traffic_history")) == 1 and len(_rows(db, "traffic_history_callers")) == 1


def test_dashboard_reads_history_through_the_keyed_proxy_route():
    import importlib.util
    spec = importlib.util.spec_from_file_location("serve_hist", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.KEYED_ROUTES["GET"].match("/api/runtime/history")
    js, html = (DEMO / "dashboard.js").read_text(), (DEMO / "index.html").read_text()
    assert '"/api/runtime/history"' in js and 'id="history-body"' in html and "never the synthetic benchmark" in html
