"""Phase 5: explainable endpoint risk (Req. 10) and alert investigation / incidents (Req. 11)."""

import sqlite3
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.endpoint_risk import FACTOR_MAX, explain_change, score_endpoint
from app.investigation import redact
from app.main import create_app
from app.storage import init_db, list_incidents, save_captured_request, save_gateway_event, upsert_alerts

KEY = "k" * 40
FP = "f" * 40
NOW = datetime(2026, 10, 14, 12, 0, 0)


def _app(tmp_path, **kw):
    return create_app(db_path=str(tmp_path / "r.db"), api_key=KEY, fp_secret=FP, clock=lambda: NOW, **kw)


def _admin(app):
    return TestClient(app, headers={"X-Sentinel-Key": KEY})


def _req(db, path, sec, *, ip="10.0.0.1", status=200, auth="none", fp=None, method="GET"):
    save_captured_request(db, method=method, path=path, status_code=status, duration_ms=1.0, client_ip=ip,
                          actor_fp=fp, auth_type=auth,
                          created_at=(NOW - timedelta(minutes=5) + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S"))


def _scrape(db, ip="10.0.0.1", n=30, start=0):
    for i in range(n):
        _req(db, f"/shop/products/{i + 1}", start + i, ip=ip)


def _alert(dtype, actor, endpoint, ts, **md):
    return {"detection_type": dtype, "actor": actor, "endpoint": endpoint, "risk_score": 40, "reason": "r",
            "timestamp": ts, "metadata": {"method": "GET", **md}}


# --- Requirement 10: endpoint risk ---------------------------------------------------------------

ITEM = {"method": "GET", "path": "/shop/orders/{id}", "data_sensitivity": "low"}


def _score(item=ITEM, *, spec="documented", gateway=True, rows=(), alerts=()):
    return score_endpoint(item, spec_status=spec, gateway_enabled=gateway, rows=list(rows), alerts=list(alerts))


def _points(result):
    return {f["factor"]: f["points"] for f in result["factors"]}


def test_baseline_endpoint_scores_zero_and_lists_unknowns():
    r = _score(rows=[{"auth_type": "bearer", "status_code": 200}] * 25)
    assert r["score"] == 0 and r["band"] == "none" and set(_points(r)) == set(FACTOR_MAX)
    assert r["unavailable_inputs"] == ["public reachability is not measured (Sentinel only sees captured traffic)"]


@pytest.mark.parametrize("kwargs,factor,points", [
    ({"spec": "shadow"}, "exposure", 15),
    ({"gateway": False}, "exposure", 5),
    ({"rows": [{"auth_type": "none", "status_code": 200}] * 25}, "authentication", 20),
    ({"rows": [{"auth_type": "basic", "status_code": 200}] * 25}, "authentication", 5),
    ({"item": {**ITEM, "data_sensitivity": "high"}}, "data_sensitivity", 15),
    ({"item": {**ITEM, "data_sensitivity": "medium"}}, "data_sensitivity", 8),
    ({"item": {**ITEM, "method": "POST"}}, "data_sensitivity", 5),
    ({"item": {**ITEM, "path": "/shop/admin/stats"}}, "data_sensitivity", 5),
])
def test_each_factor_contributes_exactly_its_documented_points(kwargs, factor, points):
    kwargs.setdefault("rows", [{"auth_type": "bearer", "status_code": 200}] * 25)
    r = _score(**kwargs)
    assert _points(r)[factor] == points and r["score"] == points
    assert any(e.startswith(f"+{points}") for f in r["factors"] for e in f["evidence"])


def test_alert_factors_count_active_types_once_and_never_double_count():
    rows = [{"auth_type": "bearer", "status_code": 200}] * 25
    a = lambda i, t, status="open": {"id": i, "detection_type": t, "endpoint": ITEM["path"], "status": status,
                                      "metadata": {"method": "GET"}}
    scraping = _score(rows=rows, alerts=[a(1, "scraping"), a(2, "scraping")])     # same type twice
    assert _points(scraping)["security_events"] == 10
    two = _score(rows=rows, alerts=[a(1, "scraping"), a(3, "token_replay")])
    assert _points(two)["security_events"] == 15
    confirmed = _score(rows=rows, alerts=[a(1, "scraping"), a(4, "bola")])
    assert _points(confirmed)["security_events"] == 25
    anomaly = _score(rows=rows, alerts=[a(5, "rate_anomaly"), a(6, "error_spike")])
    assert _points(anomaly)["behavior"] == 15 and _points(anomaly)["security_events"] == 0
    resolved = _score(rows=rows, alerts=[a(7, "bola", "resolved"), a(8, "scraping", "ignored")])
    assert _points(resolved)["security_events"] == 0
    other_method = _score(rows=rows, alerts=[{**a(9, "bola"), "metadata": {"method": "DELETE"}}])
    assert _points(other_method)["security_events"] == 0
    for r in (scraping, two, confirmed, anomaly):
        assert r["score"] == sum(_points(r).values()) and 0 <= r["score"] <= 100


def test_unknown_inputs_add_nothing_and_are_named():
    r = _score(spec="unknown", rows=[{"auth_type": "unknown", "status_code": 200}] * 3)
    assert _points(r)["exposure"] == 0 and _points(r)["authentication"] == 0 and _points(r)["behavior"] == 0
    joined = " ".join(r["unavailable_inputs"])
    assert "documentation status unknown" in joined and "auth_type" in joined and "anomaly baselines" in joined


def test_maximum_score_is_bounded():
    item = {"method": "POST", "path": "/shop/admin/export", "data_sensitivity": "high"}
    alerts = [{"id": i, "detection_type": t, "endpoint": item["path"], "status": "open", "metadata": {}}
              for i, t in enumerate(["bola", "scraping", "rate_anomaly", "error_spike", "payload_anomaly"])]
    r = _score(item, spec="shadow", gateway=False, rows=[{"auth_type": "none", "status_code": 200}] * 30,
               alerts=alerts)
    assert r["score"] == 100 and all(f["points"] <= f["max_points"] for f in r["factors"])


def test_change_is_attributed_to_factors_and_alerts():
    before = {"score": 30, "factors": {"security_events": {"points": 25, "alert_ids": [4]},
                                       "exposure": {"points": 5, "alert_ids": []}}}
    after = {"score": 5, "factors": {"security_events": {"points": 0, "alert_ids": []},
                                     "exposure": {"points": 5, "alert_ids": []}}}
    c = explain_change(before, after, "t1", "t2")
    assert c["delta"] == -25 and c["direction"] == "down" and c["no_longer_counted_alert_ids"] == [4]
    assert c["factors"] == [{"factor": "security_events", "from": 25, "to": 0, "delta": -25}]


def test_endpoint_risk_api_scores_every_endpoint_and_explains_history(tmp_path):
    app = _app(tmp_path)
    db, admin = app.state.db_path, _admin(app)
    _scrape(db)
    _req(db, "/shop/me", 40, auth="bearer", fp="fpA")
    first = admin.get("/api/risk/endpoints").json()
    assert {(i["method"], i["path"]) for i in first["items"]} == {("GET", "/shop/products/{id}"), ("GET", "/shop/me")}
    for item in first["items"]:
        assert 0 <= item["score"] <= 100 and item["score"] == sum(f["points"] for f in item["factors"])
        assert item["change"] is None and item["history"].startswith("unavailable")
    assert admin.get("/api/risk/endpoints").json() == first          # refresh: no change, nothing written

    admin.post("/api/scan")                                           # scraping alert + first snapshots
    admin.post("/api/scan")                                           # same evidence: no new snapshot
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM endpoint_risk_snapshots").fetchone()[0] == 2
    products = next(i for i in admin.get("/api/risk/endpoints").json()["items"] if i["path"] == "/shop/products/{id}")
    alert_id = next(f for f in products["factors"] if f["factor"] == "security_events")["alert_ids"][0]
    assert products["change"] is None and products["history"].startswith("one snapshot")

    assert admin.patch(f"/api/alerts/{alert_id}", json={"status": "resolved"}).status_code == 200
    products = next(i for i in admin.get("/api/risk/endpoints").json()["items"] if i["path"] == "/shop/products/{id}")
    change = products["change"]
    assert change["direction"] == "down" and change["delta"] == -10
    assert change["no_longer_counted_alert_ids"] == [alert_id]
    assert change["factors"] == [{"factor": "security_events", "from": 10, "to": 0, "delta": -10}]
    assert change["previous_at"] == change["current_at"] == NOW.isoformat()


def test_risk_endpoint_needs_the_key(tmp_path):
    assert TestClient(_app(tmp_path)).get("/api/risk/endpoints").status_code == 401


# --- Requirement 11: alert detail ----------------------------------------------------------------

def test_alert_detail_has_rule_evidence_requests_and_flagged_only_status(tmp_path):
    app = _app(tmp_path)
    db, admin = app.state.db_path, _admin(app)
    _scrape(db)
    admin.post("/api/scan")
    (alert,) = admin.get("/api/alerts").json()["items"]
    d = admin.get(f"/api/alerts/{alert['id']}").json()
    assert d["rule"]["id"] == "SCRAPE-BURST" and "requests" in d["rule"]["explanation"]
    assert d["category"] == "scraping" and d["severity"] in ("low", "medium", "high")
    assert d["disposition"] == {"status": "open", "note": None}
    assert d["enforcement"]["state"] == "flagged_only" and "reached the API" in d["enforcement"]["summary"]
    assert d["requests_matched"] == 30 and d["requests"][0]["path"] == "/shop/products/1"
    assert d["requests"][0]["status_code"] == 200 and d["requests"][0]["client_ip"] == "10.0.0.1"
    assert d["incident"]["alert_ids"] == [alert["id"]] and d["related_alerts"] == []
    assert d["risk_link"] == {"method": "GET", "path": "/shop/products/{id}"}
    assert d["alert"]["metadata"]["first_seen"] and d["provenance"] and d["missing_fields"]
    assert admin.get("/api/alerts/9999").status_code == 404
    assert TestClient(app).get(f"/api/alerts/{alert['id']}").status_code == 401


@pytest.mark.parametrize("decision,state", [("rate_limited", "rate_limited"), ("blocked", "blocked"),
                                            ("allowed", "flagged_only")])
def test_blocked_and_rate_limited_only_when_the_access_log_says_so(tmp_path, decision, state):
    app = _app(tmp_path)
    db, admin = app.state.db_path, _admin(app)
    _scrape(db)
    at = (NOW - timedelta(minutes=5, seconds=-10)).isoformat()
    save_gateway_event(db, window_start=at, seen_at=at, endpoint="GET /shop/products/{product_id}",
                       decision=decision, reason="test", status_code=429 if decision == "rate_limited" else 403,
                       identity_kind="ip", client_ip="10.0.0.1")
    save_gateway_event(db, window_start=at, seen_at=at, endpoint="GET /shop/products/{product_id}",
                       decision="blocked", reason="other caller", status_code=403, identity_kind="ip",
                       client_ip="10.9.9.9")
    admin.post("/api/scan")
    (alert,) = admin.get("/api/alerts").json()["items"]
    enforcement = admin.get(f"/api/alerts/{alert['id']}").json()["enforcement"]
    assert enforcement["state"] == state
    assert all(e["reason"] == "test" for e in enforcement["events"])  # another caller's block is not borrowed


def test_redaction_masks_credentials_and_personal_data_but_keeps_fingerprints():
    evidence = {"token_fingerprint": "abc123", "Authorization": "Bearer s3cret", "nested": {"api_key": "x",
                "note": "sent Bearer abc.def-ghi by bob@example.com"}, "list": [{"password": "p"}], "count": 3}
    out = redact(evidence)
    assert out["token_fingerprint"] == "abc123" and out["count"] == 3
    assert out["Authorization"] == out["nested"]["api_key"] == out["list"][0]["password"] == "[REDACTED]"
    assert out["nested"]["note"] == "sent Bearer [REDACTED] by [REDACTED-EMAIL]"
    assert "s3cret" not in str(out) and "abc.def" not in str(out)


def test_alert_detail_never_returns_raw_demo_tokens(tmp_path):
    app = create_app(db_path=str(tmp_path / "d.db"), api_key=KEY, fp_secret=FP, enable_demo=True)
    shop, admin = TestClient(app), _admin(app)
    for i in range(1, 6):
        shop.get(f"/shop/orders/{2 * i}", headers={"Authorization": "Bearer demo-alice-token"})
    admin.post("/api/scan")
    for alert in admin.get("/api/alerts").json()["items"]:
        detail = admin.get(f"/api/alerts/{alert['id']}").json()
        assert "demo-alice-token" not in str(detail) and detail["requests_matched"] >= 1


# --- Requirement 11: incidents --------------------------------------------------------------------

def test_incidents_group_by_category_caller_and_time_and_keep_alerts_intact(tmp_path):
    db = str(tmp_path / "i.db")
    init_db(db)
    alerts = [
        _alert("bola_enumeration", "fpM", "/shop/orders/{id}", "2026-10-14T10:00:00", x=1),
        _alert("bola", "fpM", "/shop/orders/{id}", "2026-10-14T10:20:00", x=2),          # same incident
        _alert("bola_blocked", "fpM", "/shop/secure/orders/{id}", "2026-10-14T13:00:00"),  # gap > 1 h: new
        _alert("bola", "fpOTHER", "/shop/orders/{id}", "2026-10-14T10:05:00"),           # other caller
        _alert("scraping", "fpM", "/shop/products/{id}", "2026-10-14T10:10:00"),         # other category
        _alert("rate_anomaly", "all-callers", "/shop/a", "2026-10-14T10:00:00"),          # endpoint-wide:
        _alert("rate_anomaly", "all-callers", "/shop/b", "2026-10-14T10:01:00"),          # never merged
    ]
    for a in alerts:
        upsert_alerts(db, [a])
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT id, incident_id, metadata FROM alerts ORDER BY id").fetchall()
    inc = [r[1] for r in rows]
    assert inc[0] == inc[1] and len(set(inc)) == 6
    assert '"x": 1' in rows[0][2] and '"x": 2' in rows[1][2]  # grouping keeps each alert's own evidence
    grouped = next(i for i in list_incidents(db) if i["id"] == inc[0])
    assert grouped["category"] == "bola" and grouped["alert_ids"] == [rows[0][0], rows[1][0]]
    assert grouped["first_seen"] == "2026-10-14T10:00:00" and grouped["last_seen"] == "2026-10-14T10:20:00"
    # newer evidence on an existing alert extends its incident; re-scanning old evidence changes nothing
    assert upsert_alerts(db, [alerts[1] | {"timestamp": "2026-10-14T10:40:00"}])["updated"] == 1
    assert upsert_alerts(db, [alerts[1] | {"timestamp": "2026-10-14T10:40:00"}])["unchanged"] == 1
    grouped = next(i for i in list_incidents(db) if i["id"] == inc[0])
    assert grouped["last_seen"] == "2026-10-14T10:40:00" and grouped["alert_ids"] == [rows[0][0], rows[1][0]]


def test_status_transitions_still_work_inside_an_incident(tmp_path):
    app = _app(tmp_path)
    db, admin = app.state.db_path, _admin(app)
    _scrape(db)
    admin.post("/api/scan")
    (alert,) = admin.get("/api/alerts").json()["items"]
    for status in ("acknowledged", "resolved", "ignored", "open"):
        r = admin.patch(f"/api/alerts/{alert['id']}", json={"status": status, "note": f"now {status}"})
        assert r.status_code == 200 and r.json()["status"] == status and r.json()["incident_id"] == alert["incident_id"]
    incidents = admin.get("/api/incidents").json()["items"]
    assert incidents[0]["alert_ids"] == [alert["id"]] and incidents[0]["open_alerts"] == 1


def test_alerts_stored_before_incidents_are_grouped_on_upgrade(tmp_path):
    db = str(tmp_path / "old.db")
    with sqlite3.connect(db) as conn:  # Phase 4 alerts table: no incident_id column
        conn.execute("CREATE TABLE alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, detection_type TEXT NOT NULL,"
                     " actor TEXT NOT NULL, endpoint TEXT NOT NULL, risk_score INTEGER NOT NULL, reason TEXT NOT NULL,"
                     " metadata TEXT NOT NULL DEFAULT '{}', status TEXT NOT NULL DEFAULT 'open', note TEXT,"
                     " first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, occurrences INTEGER NOT NULL DEFAULT 1,"
                     " updated_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE (detection_type, actor, endpoint))")
        for t in ("10:00:00", "10:30:00"):
            conn.execute("INSERT INTO alerts (detection_type, actor, endpoint, risk_score, reason, first_seen, last_seen,"
                         " status) VALUES ('scraping', '1.2.3.4', ?, 30, 'r', ?, ?, 'acknowledged')",
                         (f"/p{t[:2]}{t[3:5]}", f"2026-10-14T{t}", f"2026-10-14T{t}"))
    init_db(db)
    init_db(db)  # idempotent
    with sqlite3.connect(db) as conn:
        rows = conn.execute("SELECT incident_id, status FROM alerts ORDER BY id").fetchall()
    assert rows[0][0] == rows[1][0] is not None and {s for _, s in rows} == {"acknowledged"}
    assert len(list_incidents(db)) == 1
