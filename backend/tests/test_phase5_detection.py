"""Phase 5 abuse detection: rule ids + evidence, controlled BOLA outcomes, repeated
access failures and baseline anomalies. Deterministic synthetic records only."""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.analysis import (
    RULES,
    analyze_access_denied_from_captures,
    analyze_anomalies_from_captures,
    analyze_captured_traffic,
    analyze_scraping_from_captures,
    analyze_token_replay_from_captures,
)
from app.main import create_app

T0 = datetime(2026, 10, 12, 10, 0, 0)  # a Monday
KEY = "k" * 40
FP = "f" * 40


def rec(path, sec=0, *, ip="10.0.0.1", fp=None, status=200, method="GET", size=0, auth=None, t0=T0):
    return {"method": method, "path": path, "status_code": status, "client_ip": ip, "actor_fp": fp,
            "auth_type": auth or ("bearer" if fp else "none"), "payload_bytes": size,
            "created_at": (t0 + timedelta(seconds=sec)).strftime("%Y-%m-%d %H:%M:%S")}


def test_every_rule_id_used_in_metadata_is_documented():
    assert {"SCRAPE-BURST", "BOLA-CONFIRMED", "BOLA-BLOCKED", "BOLA-INCONCLUSIVE", "REPLAY-CONCURRENT",
            "AUTH-FAILURES", "ANOMALY-RATE", "ANOMALY-ERRORS", "ANOMALY-PAYLOAD"} <= set(RULES)
    for category, title, text in RULES.values():
        assert category and title and len(text) > 40


# --- A. token replay ------------------------------------------------------------------------------

def test_replay_evidence_names_the_switches_without_any_raw_token():
    recs = [rec("/shop/me", i * 5, ip=f"10.1.0.{i % 5}", fp="fpTOKEN") for i in range(10)]
    (f,) = analyze_token_replay_from_captures(recs)
    md = f["metadata"]
    assert md["rule_id"] == "REPLAY-CONCURRENT" and md["token_fingerprint"] == "fpTOKEN"
    assert md["first_seen"] == "2026-10-12T10:00:00" and md["last_seen"] == "2026-10-12T10:00:45"
    assert md["endpoints"] == ["GET /shop/me"] and md["status_counts"] == {"200": 10}
    assert md["ip_switches"][0] == {"at": "2026-10-12T10:00:05", "from_ip": "10.1.0.0", "to_ip": "10.1.0.1",
                                    "gap_seconds": 5.0}
    assert md["distinct_ips"] == 5 and md["auth_types"] == ["bearer"]


def test_legitimate_reuse_retries_roaming_and_anonymous_traffic_are_not_replay():
    retries = [rec("/shop/me", i, fp="fpA") for i in range(50)]                       # one IP, many uses
    roaming = [rec("/shop/me", i * 900, ip=f"10.2.0.{i}", fp="fpB") for i in range(5)]  # 15 min apart
    anonymous = [rec("/shop/me", i, ip=f"10.3.0.{i}") for i in range(10)]              # no identity
    assert analyze_token_replay_from_captures(retries + roaming + anonymous) == []


# --- B. scraping ----------------------------------------------------------------------------------

def test_scraping_evidence_shows_sequential_walk():
    (f,) = analyze_scraping_from_captures([rec(f"/shop/products/{i}", i) for i in range(1, 31)])
    md = f["metadata"]
    assert md["rule_id"] == "SCRAPE-BURST" and md["sequential_id_run"] == 30
    assert md["endpoints"] == ["GET /shop/products/{id}"] and md["first_seen"] == "2026-10-12T10:00:01"


def test_pagination_of_one_list_and_a_normal_peak_on_few_paths_are_not_scraping():
    pages = [rec(f"/shop/products?page={i}", i) for i in range(40)]  # query values are not new objects
    peak = [rec(f"/shop/me" if i % 2 else "/shop/products/1", i, ip="10.9.9.9") for i in range(60)]
    assert analyze_scraping_from_captures(pages + peak) == []


# --- C. BOLA: controlled cross-user test against the demo shop only ---------------------------------

def test_demo_shop_cross_user_access_is_confirmed_and_secure_route_attempt_is_blocked(tmp_path):
    app = create_app(db_path=str(tmp_path / "b.db"), api_key=KEY, fp_secret=FP, enable_demo=True)
    shop = TestClient(app)
    alice = {"Authorization": "Bearer demo-alice-token"}  # alice owns odd orders, bob even ones
    assert shop.get("/shop/orders/1", headers=alice).status_code == 200          # own object
    assert shop.get("/shop/orders/2", headers=alice).status_code == 200          # bob's: disclosed
    assert shop.get("/shop/secure/orders/4", headers=alice).status_code == 403   # bob's: refused
    assert shop.get("/shop/secure/orders/3", headers=alice).status_code == 200   # own, fixed route
    admin = TestClient(app, headers={"X-Sentinel-Key": KEY})
    assert admin.post("/api/scan").status_code == 200
    alerts = {a["detection_type"]: a for a in admin.get("/api/alerts").json()["items"]}
    assert set(alerts) == {"bola", "bola_blocked"}
    confirmed, blocked = alerts["bola"], alerts["bola_blocked"]
    assert confirmed["endpoint"] == "/shop/orders/{id}" and confirmed["metadata"]["object_ids"] == ["2"]
    assert confirmed["metadata"]["rule_id"] == "BOLA-CONFIRMED" and confirmed["metadata"]["user_id"] == "alice"
    assert blocked["endpoint"] == "/shop/secure/orders/{id}" and blocked["metadata"]["outcome"] == "blocked"
    assert blocked["metadata"]["status_counts"] == {"403": 1} and blocked["risk_score"] < confirmed["risk_score"]
    assert "demo-alice-token" not in str(alerts)


def test_demo_ownership_is_not_used_outside_demo_mode(tmp_path):
    app = create_app(db_path=str(tmp_path / "n.db"), api_key=KEY, fp_secret=FP, enable_demo=False)
    assert app.state.ownership is None


# --- D. unauthorized access ----------------------------------------------------------------------

def test_repeated_denials_fire_with_evidence_and_a_few_do_not():
    noisy = [rec(p, i * 3, ip="10.4.0.1", status=401) for i, p in
             enumerate(["/shop/admin/stats", "/shop/internal/export", "/shop/me"] * 4)]
    (f,) = analyze_access_denied_from_captures(noisy)
    md = f["metadata"]
    assert f["detection_type"] == "access_denied" and md["rule_id"] == "AUTH-FAILURES"
    assert md["denied_count"] == 12 and md["denied_ratio"] == 1.0 and md["without_credentials"] == 12
    assert set(md["endpoints"]) == {"GET /shop/admin/stats", "GET /shop/internal/export", "GET /shop/me"}
    few = [rec("/shop/me", i, ip="10.4.0.2", status=401) for i in range(5)]
    mostly_ok = [rec("/shop/me", i, ip="10.4.0.3", status=200 if i % 3 else 403) for i in range(40)]
    assert analyze_access_denied_from_captures(few + mostly_ok) == []


def test_denials_explained_by_enumeration_are_not_alerted_twice():
    walk = [rec(f"/shop/orders/{i}", i * 2, ip="10.5.0.1", status=403) for i in range(20, 40)]
    types = [f["detection_type"] for f in analyze_captured_traffic(walk)]
    assert "bola_enumeration" in types and "access_denied" not in types


# --- D. baseline anomalies -------------------------------------------------------------------------

def _weekly_history(weeks, per_hour, path="/shop/products/1", **kw):
    out = []
    for w in range(1, weeks + 1):
        t0 = T0 - timedelta(weeks=w)
        out += [rec(path, i * 30, t0=t0, ip=f"10.6.{w}.{i % 3}", **kw) for i in range(per_hour)]
    return out


def test_rate_anomaly_needs_matching_history_and_ignores_a_recurring_peak():
    now = T0 + timedelta(minutes=50)
    spike = [rec("/shop/products/1", i * 10, ip=f"10.7.0.{i % 20}") for i in range(200)]
    rate = lambda recs: [f for f in analyze_anomalies_from_captures(recs, now=now) if f["detection_type"] == "rate_anomaly"]
    endpoint = [f for f in rate(_weekly_history(3, 10) + spike) if f["metadata"]["actor"] == "all-callers"]
    assert len(endpoint) == 1 and endpoint[0]["metadata"]["rule_id"] == "ANOMALY-RATE"
    assert endpoint[0]["metadata"]["baseline_samples"] == 3 and endpoint[0]["metadata"]["current_hour_requests"] == 200
    assert rate(spike) == []                                     # first-ever busy hour: no history, no alert
    assert rate(_weekly_history(3, 200) + spike) == []          # the same peak every Monday 10:00


def test_error_spike_and_payload_anomaly_need_history():
    now = T0 + timedelta(minutes=10)
    history = [rec("/shop/upload", -3600 * h, method="POST", size=200, ip="10.8.0.1") for h in range(1, 31)]
    errors = [rec("/shop/upload", 400 + i, method="POST", status=503, size=200, ip="10.8.0.2") for i in range(12)]
    big = [rec("/shop/upload", 500, method="POST", size=50_000, ip="10.8.0.3", fp="fpBIG")]
    found = {f["detection_type"]: f for f in analyze_anomalies_from_captures(history + errors + big, now=now)}
    assert set(found) == {"error_spike", "payload_anomaly"}
    assert found["error_spike"]["metadata"]["server_errors"] == 12 and found["error_spike"]["metadata"]["baseline_error_ratio"] == 0
    md = found["payload_anomaly"]["metadata"]
    assert md["actor"] == "fpBIG" and md["max_payload_bytes"] == 50_000 and md["payload_limit_bytes"] == 1024
    assert analyze_anomalies_from_captures(errors + big, now=now) == []  # no baseline: silent
