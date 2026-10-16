"""CC6-IC07 finalization: slow enumeration, risk-score coverage, inventory metadata, shadow
distinctions, baseline states and the cleaned-up dashboard chrome."""

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.analysis import analyze_captured_traffic, analyze_enumeration_from_captures
from app.discovery import build_inventory
from app.main import create_app
from app.runtime_monitor import build_runtime_baselines
from app.storage import init_db, save_captured_request

KEY = "k" * 40
T0 = datetime(2026, 10, 12, 10, 0, 0)  # Monday
DEMO = Path(__file__).resolve().parents[2] / "demo"
INDEX = (DEMO / "index.html").read_text()
JS = (DEMO / "dashboard.js").read_text()


def rec(path, sec=0, *, ip="10.0.0.1", fp=None, status=200, method="GET", auth=None, t0=T0):
    return {"method": method, "path": path, "status_code": status, "client_ip": ip, "actor_fp": fp,
            "auth_type": auth or ("bearer" if fp else "none"),
            "created_at": (t0 + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S")}


# --- D. low-and-slow enumeration (separate fixture, not the benchmark scenarios) -------------------

def test_slow_paced_id_probing_is_flagged_as_an_attempt():
    probe = [rec(f"/api/invoices/{500 + k}", 150 * k, fp="fpEVE", status=403) for k in range(14)]  # 33 min
    (f,) = analyze_enumeration_from_captures(probe)
    md = f["metadata"]
    assert f["detection_type"] == "bola_enumeration" and md["rule_id"] == "BOLA-ENUM-SLOW"
    assert md["pattern"] == "low_and_slow" and md["window_seconds"] == 3600 and md["distinct_ids"] == 14
    assert md["outcome"] == "attempt" and "Low-and-slow" in f["reason"]
    assert analyze_enumeration_from_captures(probe, detect_low_and_slow=False) == []


def test_a_fast_probe_keeps_the_burst_rule():
    (f,) = analyze_enumeration_from_captures([rec(f"/api/invoices/{k}", k, status=404) for k in range(20)])
    assert f["metadata"]["rule_id"] == "BOLA-ENUM" and f["metadata"]["pattern"] == "burst"


@pytest.mark.parametrize("records", [
    [rec(f"/api/invoices/{k}", 150 * k, fp="fpOWN") for k in range(14)],               # slow reads, all 200
    [rec(f"/api/invoices/{k}", 150 * k, fp="fpTYPO", status=404) for k in range(6)],   # a few slow misses
    [rec(f"/api/invoices/{k}", 400 * k, fp="fpSLOW", status=404) for k in range(14)],  # > 1 h apart overall
])
def test_slow_benign_patterns_are_not_enumeration(records):
    assert analyze_enumeration_from_captures(records) == []


def test_denials_from_a_slow_probe_are_not_also_counted_as_access_failures():
    probe = [rec(f"/api/invoices/{k}", 150 * k, ip="10.9.9.9", status=401) for k in range(14)]
    types = [f["detection_type"] for f in analyze_captured_traffic(probe)]
    assert types.count("bola_enumeration") == 1 and "access_denied" not in types


# --- A/E. inventory metadata and risk coverage ----------------------------------------------------

def _db(tmp_path, rows):
    db = str(tmp_path / "c.db")
    init_db(db)
    for r in rows:
        save_captured_request(db, method=r["method"], path=r["path"], status_code=r["status_code"], duration_ms=1,
                              client_ip=r["client_ip"], actor_fp=r["actor_fp"], auth_type=r["auth_type"],
                              created_at=r["created_at"])
    return db


def test_normalization_collisions_and_missing_metadata():
    inv = {(i["method"], i["path"]): i for i in build_inventory([
        rec("/users/1"), rec("/users/2"), rec("/users/me"), rec("/users/3", method="DELETE"),
        rec("/files/550e8400-e29b-41d4-a716-446655440000"), {"method": "GET", "path": "/legacy", "status_code": 200,
                                                             "created_at": "2026-10-12 10:00:00"},
        rec("/nothing", status=404), rec("/users/4?email=x@example.com")])}
    assert inv[("GET", "/users/{id}")]["request_count"] == 3 and ("GET", "/users/me") in inv
    assert ("DELETE", "/users/{id}") in inv and ("GET", "/files/{id}") in inv
    assert inv[("GET", "/legacy")]["authentication_types"] == ["unknown"]  # no auth info: explicit unknown
    assert inv[("GET", "/users/{id}")]["query_params"] == ["email"]          # names only, never values
    assert "email" in inv[("GET", "/users/{id}")]["sensitivity_basis"]
    assert "no sensitive name" in inv[("GET", "/legacy")]["sensitivity_basis"]
    assert inv[("GET", "/nothing")]["confirmed_live"] is False and inv[("GET", "/legacy")]["confirmed_live"] is True


def test_every_discovered_endpoint_is_scored_or_listed_as_excluded(tmp_path):
    rows = [rec(f"/shop/products/{i}", i) for i in range(25)] + [rec("/shop/me", 30, fp="fpA")] \
        + [rec("/", 31, status=404), rec("/favicon.ico", 32, status=404), rec("/shop/x", 33, method="POST", status=405)]
    admin = TestClient(create_app(db_path=_db(tmp_path, rows), api_key=KEY), headers={"X-Sentinel-Key": KEY})
    inventory = {(i["method"], i["path"]) for i in admin.get("/api/inventory").json()["items"]}
    risk = admin.get("/api/risk/endpoints").json()
    scored = {(i["method"], i["path"]) for i in risk["items"]}
    excluded = {(i["method"], i["path"]) for i in risk["excluded"]}
    assert scored | excluded == inventory and not scored & excluded  # same identities, nothing silently dropped
    assert excluded == {("GET", "/"), ("GET", "/favicon.ico"), ("POST", "/shop/x")}
    assert risk["coverage"] == {"discovered": 5, "scored": 2, "not_scored": 3}
    assert all("404/405" in e["reason"] for e in risk["excluded"])
    for item in risk["items"]:
        assert 0 <= item["score"] <= 100 and item["band"] in ("none", "low", "medium", "high") and item["explanation"]
        assert item["confidence"] in ("provisional", "established") and item["confidence_reason"]
    by_path = {i["path"]: i for i in risk["items"]}
    assert by_path["/shop/me"]["confidence"] == "provisional" and "only 1 captured" in by_path["/shop/me"]["confidence_reason"]
    assert admin.get("/api/risk/endpoints").json() == risk  # deterministic, read-only


def test_score_is_established_only_with_enough_traffic_and_known_inputs(tmp_path, monkeypatch):
    spec = tmp_path / "s.json"
    spec.write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                                "paths": {"/shop/products/{productId}": {"get": {}}}}))
    monkeypatch.setenv("OPENAPI_SPEC_PATH", str(spec))
    from app.config import get_settings
    get_settings.cache_clear()
    try:
        rows = [rec(f"/shop/products/{i}", i, fp="fpA") for i in range(25)]
        admin = TestClient(create_app(db_path=_db(tmp_path, rows), api_key=KEY), headers={"X-Sentinel-Key": KEY})
        (item,) = admin.get("/api/risk/endpoints").json()["items"]
        assert item["confidence"] == "established" and "25 captured requests" in item["confidence_reason"]
    finally:
        get_settings.cache_clear()


# --- B. shadow distinctions ---------------------------------------------------------------------

def test_shadow_classification_keeps_old_routes_and_ignores_sentinel_and_404_routes(tmp_path):
    specs = tmp_path / "specs"
    specs.mkdir()
    (specs / "s.json").write_text(json.dumps({"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
                                              "paths": {"/api/products": {"get": {}}}}))
    old = datetime(2025, 1, 1)
    rows = [rec("/api/products", 0), rec("/internal/metrics", 0, t0=old), rec("/api/debug/config", 5),
            rec("/admin.php", 6, status=404), rec("/api/inventory", 7)]
    db = _db(tmp_path, rows)
    admin = TestClient(create_app(db_path=db, api_key=KEY, spec_dir=str(specs)), headers={"X-Sentinel-Key": KEY})
    body = admin.get("/api/shadow-apis", params={"spec_path": str(specs / "s.json")}).json()
    assert sorted(r["path"] for r in body["shadow_apis"]) == ["/api/debug/config", "/internal/metrics"]  # old route kept
    assert [r["path"] for r in body["documented"]] == ["/api/products"]
    assert body["unmanaged_apis"] == [] and "registry" in body["unmanaged_note"]


# --- C. baseline states ---------------------------------------------------------------------------

def _week(weeks, per_hour):
    return [rec("/p/1", i * 30, t0=T0 - timedelta(weeks=w)) for w in range(1, weeks + 1) for i in range(per_hour)]


@pytest.mark.parametrize("history,current,state", [
    (0, 5, "no_baseline"), (2, 5, "insufficient"), (3, 10, "ready"), (3, 200, "deviation")])
def test_baseline_states(history, current, state):
    records = _week(history, 10) + [rec("/p/1", i * 5) for i in range(current)]
    (endpoint,) = build_runtime_baselines(records, now=T0 + timedelta(minutes=50))["endpoints"]
    assert endpoint["baseline_state"] == state and endpoint["rate_anomaly"] is (state == "deviation")


# --- UI: header and footer ------------------------------------------------------------------------

def test_header_shows_only_the_product_name():
    header = re.search(r'<header class="top">(.*?)</header>', INDEX, re.S).group(1)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", header)).strip()
    assert text == "API Sentinel"
    for gone in ('id="conn"', 'id="last-refresh"', 'id="auto"', 'id="density"', "local demo dashboard", "Auto-refresh"):
        assert gone not in header
    access = INDEX.split('id="tab-access"')[1].split('id="tab-evaluation"')[0]
    for kept in ('id="conn"', 'id="conn-detail"', 'id="last-refresh"', 'id="auto"', 'id="density"'):
        assert kept in access  # status, refresh time and settings live in Diagnostics now


def test_repeated_footer_disclaimer_is_gone():
    assert "<footer" not in INDEX
    assert "this page computes nothing about risk itself" not in INDEX + JS
    assert "Scores come from the backend" not in INDEX
