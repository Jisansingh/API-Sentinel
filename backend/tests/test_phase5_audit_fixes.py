"""Regressions for defects found on the live revision 5 dashboard (audit, 2026-10-16)."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.discovery import is_self_route
from app.investigation import related_by_caller
from app.main import create_app
from app.storage import init_db, save_captured_request, upsert_alerts

KEY = "k" * 40
FP = "f" * 40
DEMO = Path(__file__).resolve().parents[2] / "demo"
JS = (DEMO / "dashboard.js").read_text()
MALLORY = {"Authorization": "Bearer demo-mallory-token"}


def _demo(tmp_path):
    app = create_app(db_path=str(tmp_path / "a.db"), api_key=KEY, fp_secret=FP, enable_demo=True)
    return app, TestClient(app), TestClient(app, headers={"X-Sentinel-Key": KEY})


def _by_type(admin):
    return {a["detection_type"]: a for a in admin.get("/api/alerts").json()["items"]}


# --- A. BOLA evidence is filtered by outcome ----------------------------------------------------

def test_confirmed_bola_evidence_excludes_the_enumeration_404s(tmp_path):
    """Live alert #7: mallory walked orders 1-30 (10 exist -> 200, 20 missing -> 404). The confirmed
    BOLA alert's evidence is the 10 content-bearing reads; the 404s belong to the enumeration alert."""
    _, shop, admin = _demo(tmp_path)
    for i in range(1, 31):
        shop.get(f"/shop/orders/{i}", headers=MALLORY)
    admin.post("/api/scan")
    alerts = _by_type(admin)
    bola = admin.get(f"/api/alerts/{alerts['bola']['id']}").json()
    assert bola["alert"]["metadata"]["unauthorized_objects"] == 10
    assert bola["requests_matched"] == 10 and {r["status_code"] for r in bola["requests"]} == {200}
    assert sorted(int(r["path"].rsplit("/", 1)[1]) for r in bola["requests"]) == list(range(1, 11))
    enum = admin.get(f"/api/alerts/{alerts['bola_enumeration']['id']}").json()
    assert enum["requests_matched"] == 30  # the probing walk itself, 404s included


def test_blocked_evidence_uses_refusals_only_and_known_objects(tmp_path):
    _, shop, admin = _demo(tmp_path)
    assert shop.get("/shop/secure/orders/2", headers=MALLORY).status_code == 403  # bob's order: refused
    assert shop.get("/shop/secure/orders/99", headers=MALLORY).status_code == 404  # no such order: no owner
    shop.get("/shop/orders/4", headers=MALLORY)                                     # other route, disclosed
    admin.post("/api/scan")
    alerts = _by_type(admin)
    blocked = admin.get(f"/api/alerts/{alerts['bola_blocked']['id']}").json()
    assert [r["path"] for r in blocked["requests"]] == ["/shop/secure/orders/2"]
    assert blocked["enforcement"]["state"] == "flagged_only"  # refused by the API itself, not by Sentinel


def test_204_is_inconclusive_evidence_not_confirmed(tmp_path):
    db = str(tmp_path / "x.db")
    init_db(db)
    own = {"resources": {"/o/{id}": {"1": "bob"}}, "actors": {"fpM": "mallory"}}
    for status in (204, 200):
        save_captured_request(db, method="GET", path="/o/1", status_code=status, duration_ms=1, client_ip="10.0.0.5",
                              actor_fp="fpM", created_at="2026-10-14 10:00:00")
    app = create_app(db_path=db, api_key=KEY, ownership=own)
    admin = TestClient(app, headers={"X-Sentinel-Key": KEY})
    admin.post("/api/scan")
    alerts = _by_type(admin)
    for dtype, status in (("bola", 200), ("bola_inconclusive", 204)):
        d = admin.get(f"/api/alerts/{alerts[dtype]['id']}").json()
        assert [r["status_code"] for r in d["requests"]] == [status], dtype


# --- B/C. legacy duplicates and cross-category related alerts ---------------------------------------

def _alert(dtype, actor, endpoint, ts, **md):
    return {"detection_type": dtype, "actor": actor, "endpoint": endpoint, "risk_score": 40, "reason": "r",
            "timestamp": ts, "metadata": {"method": "GET", **md}}


def test_legacy_ip_alert_is_linked_to_the_credential_alert_as_a_possible_duplicate(tmp_path):
    db = str(tmp_path / "d.db")
    init_db(db)
    upsert_alerts(db, [
        _alert("scraping", "10.0.0.77", "/shop/orders/{id}", "2026-10-15T06:51:45", client_ip="10.0.0.77"),   # legacy
        _alert("scraping", "fpMAL", "/shop/orders/{id}", "2026-10-15T06:51:45", client_ip="10.0.0.77",
               actor_type="credential", rule_id="SCRAPE-BURST"),
        _alert("bola", "fpMAL", "/shop/orders/{id}", "2026-10-15T06:51:45", client_ip="10.0.0.77", rule_id="BOLA-CONFIRMED",
               outcome="confirmed", object_ids=["1"], unauthorized_objects=1),
        _alert("scraping", "10.9.9.9", "/shop/orders/{id}", "2026-10-15T06:51:45", client_ip="10.9.9.9"),     # other caller
        _alert("scraping", "fpMAL", "/shop/products/{id}", "2026-10-15T12:00:00", client_ip="10.0.0.77"),     # 5 h later
    ])
    app = create_app(db_path=db, api_key=KEY)
    admin = TestClient(app, headers={"X-Sentinel-Key": KEY})
    legacy = admin.get("/api/alerts/1").json()
    assert legacy["legacy"] is True and legacy["rule"] is None
    related = {r["id"]: r for r in legacy["related_by_caller"]}
    assert set(related) == {2, 3}
    assert related[2]["possible_duplicate"] is True and related[2]["shared"] == ["10.0.0.77"]
    assert related[3]["possible_duplicate"] is False
    current = admin.get("/api/alerts/2").json()
    assert current["legacy"] is False and {r["id"] for r in current["related_by_caller"]} == {1, 3}
    # read-only: statuses and incidents untouched, and incidents stay per category
    alerts = admin.get("/api/alerts").json()["items"]
    assert {a["status"] for a in alerts} == {"open"}
    assert len({a["incident_id"] for a in alerts if a["id"] in (2, 3)}) == 2


def test_related_by_caller_ignores_endpoint_wide_anomalies():
    a = {"id": 1, "actor": "all-callers", "first_seen": "2026-10-15T06:00:00", "last_seen": "2026-10-15T06:00:00",
         "metadata": {}, "detection_type": "rate_anomaly", "endpoint": "/a", "status": "open", "risk_score": 20}
    b = {**a, "id": 2, "endpoint": "/b"}
    assert related_by_caller(a, [a, b]) == []


# --- discovery / risk: internal and 404-only routes ----------------------------------------------

def test_proxy_status_is_internal_and_404_only_routes_get_no_risk_score(tmp_path):
    assert is_self_route("/api/proxy-status")
    db = str(tmp_path / "r.db")
    init_db(db)
    for path, status in (("/api/proxy-status", 404), ("/favicon.ico", 404), ("/login.html", 404), ("/shop/me", 200)):
        save_captured_request(db, method="GET", path=path, status_code=status, duration_ms=1, client_ip="1.2.3.4",
                              auth_type="none", created_at="2026-10-14 10:00:00")
    admin = TestClient(create_app(db_path=db, api_key=KEY), headers={"X-Sentinel-Key": KEY})
    inventory = {i["path"] for i in admin.get("/api/inventory").json()["items"]}
    assert "/api/proxy-status" not in inventory and {"/favicon.ico", "/shop/me"} <= inventory
    risk = admin.get("/api/risk/endpoints").json()
    assert [(i["method"], i["path"]) for i in risk["items"]] == [("GET", "/shop/me")]
    assert "404/405" in risk["not_scored"]


# --- Requirement 7: deprecated and unmanaged are not conflated -------------------------------------

def test_deprecated_apis_reach_the_client_and_unmanaged_is_not_guessed(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "s.json").write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"}, "paths": {
        "/old/{id}": {"get": {"deprecated": True}}, "/new/{id}": {"get": {}}}}))
    db = str(tmp_path / "s.db")
    init_db(db)
    for path in ("/old/1", "/new/1", "/hidden/1"):
        save_captured_request(db, method="GET", path=path, status_code=200, duration_ms=1, client_ip="1.2.3.4")
    admin = TestClient(create_app(db_path=db, api_key=KEY, spec_dir=str(specs)), headers={"X-Sentinel-Key": KEY})
    body = admin.get("/api/shadow-apis", params={"spec_path": str(specs / "s.json")}).json()
    assert [(r["method"], r["path"]) for r in body["shadow_apis"]] == [("GET", "/hidden/{id}")]
    assert [(r["method"], r["path"]) for r in body["deprecated_apis"]] == [("GET", "/old/{id}")]
    assert body["unmanaged_apis"] == [] and "registry" in body["unmanaged_note"]


# --- D. detection chart --------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_detection_chart_has_one_row_per_stored_type_with_real_counts():
    block = re.search(r"/\* detection-type-rows:start.*?\*/(.*?)/\* detection-type-rows:end \*/", JS, re.S).group(1)
    labels = re.search(r"const TYPE_LABELS = (\{.*?\n\});", JS, re.S).group(1)
    alerts = [{"detection_type": t} for t in ["scraping"] * 4 + ["bola", "bola_enumeration", "token_replay", "new_type"]]
    script = f"const TYPE_LABELS = {labels};\n{block}\nconsole.log(JSON.stringify(detectionTypeRows(JSON.parse(process.argv[1]), TYPE_LABELS)));"
    rows = json.loads(subprocess.run(["node", "-e", script, json.dumps(alerts)], capture_output=True, text=True, check=True).stdout)
    assert [(r["type"], r["value"]) for r in rows] == [("scraping", 4), ("bola", 1), ("bola_enumeration", 1),
                                                        ("new_type", 1), ("token_replay", 1)]
    assert sum(r["value"] for r in rows) == len(alerts)
    assert {r["type"]: r["label"] for r in rows}["new_type"] == "new_type"  # unknown types still shown, raw
    assert {r["type"]: r["label"] for r in rows}["bola"] == "BOLA (confirmed)"
    assert "Alerts by detection type" in JS and "Alerts by detection category" not in JS
    assert "INC-" in JS  # incident ids are labelled so they are not read as alert ids


def test_mobile_nav_is_not_stretched_by_the_desktop_flex_basis():
    """At <= 900 px the shell becomes a column; the sidebar's 208px flex-basis then set its HEIGHT,
    stretching each tab button to ~200px at 390px wide. The media query must reset the basis."""
    css = (DEMO / "dashboard.css").read_text()
    narrow = css.split("@media (max-width: 900px) {", 1)[1].split("\n}", 1)[0]
    assert re.search(r"\.side-nav \{ flex: 0 0 auto;", narrow)
    sizes = [float(s) for s in re.findall(r"font-size: *([0-9.]+)px", css)]
    assert min(sizes) >= 11  # nothing below 11px (only the tiny tab badge is 11px; body text >= 12px)


# --- enforcement attribution: only events for the alert's own endpoints count ----------------------

def _scrape_alert_with_events(tmp_path, events):
    """Shadow-lab reproduction: a same-IP SCRAPE-BURST (all 200) plus access-control events."""
    from datetime import datetime, timedelta

    from app.storage import save_gateway_event

    now = datetime(2026, 10, 15, 23, 20, 12)
    db = str(tmp_path / "e.db")
    init_db(db)
    for i in range(30):
        save_captured_request(db, method="GET", path=f"/api/products/{i + 1}", status_code=200, duration_ms=1,
                              client_ip="127.0.0.1", created_at=(now - timedelta(seconds=30 - i)).strftime("%Y-%m-%d %H:%M:%S"))
    at = (now - timedelta(seconds=5)).isoformat()
    for endpoint, decision, reason in events:
        save_gateway_event(db, window_start=at, seen_at=at, endpoint=endpoint, decision=decision, reason=reason,
                           status_code=429 if decision == "rate_limited" else 404, identity_kind="ip",
                           client_ip="127.0.0.1")
    admin = TestClient(create_app(db_path=db, api_key=KEY, clock=lambda: now), headers={"X-Sentinel-Key": KEY})
    admin.post("/api/scan")
    (alert,) = admin.get("/api/alerts").json()["items"]
    detail = admin.get(f"/api/alerts/{alert['id']}").json()
    return alert, detail


UNMATCHED = "ANY /gateway/* (no matching route)"


def test_unrelated_same_ip_denials_do_not_make_an_alert_blocked(tmp_path):
    """The live shadow-lab bug: 3 route_not_allowed + 1 method_not_allowed probes from the same IP in the
    same minute turned a SCRAPE-BURST whose 30 requests all returned 200 into 'blocked'."""
    alert, d = _scrape_alert_with_events(tmp_path, [(UNMATCHED, "blocked", "route_not_allowed")] * 3
                                         + [(UNMATCHED, "blocked", "method_not_allowed"),
                                            ("GET /gateway/api/status", "blocked", "route_forbidden"),
                                            ("POST /gateway/api/products/{product_id}", "blocked", "role_forbidden")])
    e = d["enforcement"]
    assert e["state"] == "flagged_only" and e["blocked"] == 0 and e["events"] == []
    # 3 + 1 unmatched probes, one other GET route, one POST on the same path (alert evidence is GET only)
    assert e["unrelated_events"] == 6 and "other routes" in e["summary"]
    assert alert["detection_type"] == "scraping" and alert["metadata"]["rule_id"] == "SCRAPE-BURST"
    assert {r["status_code"] for r in d["requests"]} == {200}


@pytest.mark.parametrize("endpoint", ["GET /gateway/api/products/{product_id}", "GET /api/products/{product_id}"])
@pytest.mark.parametrize("decision,state", [("blocked", "blocked"), ("rate_limited", "rate_limited")])
def test_matching_gateway_or_rate_limit_events_still_count(tmp_path, endpoint, decision, state):
    alert, d = _scrape_alert_with_events(tmp_path, [(endpoint, decision, "test"), (UNMATCHED, "blocked", "route_not_allowed")])
    e = d["enforcement"]
    assert e["state"] == state and e[decision] == 1 and [x["endpoint"] for x in e["events"]] == [endpoint]
    assert alert["risk_score"] == 40 and alert["status"] == "open"  # detection/severity untouched


@pytest.mark.parametrize("endpoint", ["", "ANY /gateway/*", "GET", "GET /gateway/*", "BLOCKED something", "GET api/products/{id}"])
def test_missing_or_wildcard_event_routes_never_match(endpoint):
    from app.investigation import event_route

    assert event_route(endpoint) is None
    assert event_route("GET /gateway/api/products/{product_id}") == "GET /api/products/{id}"
