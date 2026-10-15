"""Phase 2 detector changes: scraping gate + low-and-slow, concurrent-use token
replay, ownership-based confirmed BOLA."""

import json
import sqlite3
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.analysis import (
    alert_actor,
    analyze_credential_rotation_from_captures,
    analyze_captured_traffic,
    analyze_scraping_from_captures,
    analyze_token_replay_from_captures,
    analyze_unauthorized_access_from_captures,
)
from app.main import create_app
from app.ownership import load_ownership, validate_ownership
from app.storage import init_db

T0 = datetime(2026, 10, 14, 0, 0, 0)
KEY = "a" * 32
OWN = {"resources": {"/shop/orders/{id}": {"1": "alice", "2": "bob", "3": "alice"}},
       "actors": {"fpALICE": "alice", "fpMAL": "mallory", "10.0.0.9": "mallory"}}


def _rec(path, second=0, ip="1.2.3.4", fp=None, status=200, method="GET"):
    return {"method": method, "path": path, "status_code": status, "duration_ms": 1.0, "client_ip": ip,
            "actor_fp": fp, "created_at": (T0 + timedelta(seconds=second)).strftime("%Y-%m-%d %H:%M:%S")}


# --- scraping --------------------------------------------------------------------

def test_polling_one_endpoint_is_not_scraping_but_many_objects_are():
    polling = [_rec("/api/status", second=i) for i in range(40)]
    assert analyze_scraping_from_captures(polling) == []
    four_paths = [_rec(f"/api/items/{i % 4}", second=i) for i in range(40)]
    assert analyze_scraping_from_captures(four_paths) == []        # < 5 distinct: still quiet
    five_paths = [_rec(f"/api/items/{i % 5}", second=i) for i in range(40)]
    (f,) = analyze_scraping_from_captures(five_paths)
    assert f["metadata"]["pattern"] == "burst"
    assert analyze_scraping_from_captures(polling, min_distinct_for_rate=1)  # Phase 1 rule is still reachable


def test_distinct_object_rule_is_unaffected_by_the_gate():
    walk = [_rec(f"/api/items/{i}", second=i * 3) for i in range(25)]  # 21 distinct inside 60 s
    assert analyze_scraping_from_captures(walk)


def test_low_and_slow_harvest_is_flagged_and_labelled():
    slow = [_rec(f"/api/items/{i % 30}", second=i * 20) for i in range(150)]  # 50 min, 30 objects
    (f,) = analyze_scraping_from_captures(slow)
    assert f["metadata"]["pattern"] == "low_and_slow"
    assert f["reason"].startswith("Low-and-slow") and f["risk_score"] >= 30
    few = [_rec(f"/api/items/{i % 3}", second=i * 20) for i in range(150)]
    assert analyze_scraping_from_captures(few) == []


def test_low_and_slow_can_be_disabled():
    slow = [_rec(f"/api/items/{i % 30}", second=i * 20) for i in range(150)]
    assert analyze_scraping_from_captures(slow, detect_low_and_slow=False) == []


def test_separate_credentials_behind_one_nat_ip_are_not_one_scraper():
    # Six users, each with their own credential, all egress through 10.9.9.9.
    # Each makes 4 ordinary requests; together they look like a burst from one IP.
    nat = [_rec(f"/api/items/{u * 4 + k}", second=u * 8 + k * 2, ip="10.9.9.9", fp=f"fpUSER{u}")
           for u in range(6) for k in range(4)]
    assert analyze_scraping_from_captures(nat) == []


def test_one_credential_scraping_is_detected_next_to_nat_neighbours():
    scraper = [_rec(f"/api/items/{i}", second=i * 0.5, ip="10.9.9.9", fp="fpSCRAPER") for i in range(40)]
    neighbours = [_rec(f"/api/items/{100 + u * 4 + k}", second=u * 8 + k * 2, ip="10.9.9.9", fp=f"fpUSER{u}")
                  for u in range(6) for k in range(4)]
    (f,) = analyze_scraping_from_captures(scraper + neighbours)
    assert f["detection_type"] == "scraping"
    assert f["metadata"]["actor"] == "fpSCRAPER" and f["metadata"]["actor_type"] == "credential"
    assert alert_actor(f) == "fpSCRAPER"


def test_anonymous_scraper_is_still_detected_by_ip():
    anon = [_rec(f"/api/items/{i}", second=i * 0.5, ip="10.8.8.8") for i in range(40)]
    (f,) = analyze_scraping_from_captures(anon)
    assert f["metadata"]["actor"] == "10.8.8.8" and f["metadata"]["actor_type"] == "ip"
    assert alert_actor(f) == "10.8.8.8"


# --- credential rotation (one IP, many credential fingerprints) ----------------------

def _rotating(ip="10.7.7.7", creds=40, start=0):
    """One request per fresh credential, distinct paths, from one IP."""
    return [_rec(f"/api/items/{start + i}", second=i * 0.5, ip=ip, fp=f"fpROT{start + i}") for i in range(creds)]


def _nat_users(users, per_user, ip="10.9.9.9"):
    return [_rec(f"/api/items/{u * per_user + k}", second=u * 8 + k * 2, ip=ip, fp=f"fpUSER{u}")
            for u in range(users) for k in range(per_user)]


def test_credential_rotation_from_one_ip_is_flagged():
    (f,) = analyze_credential_rotation_from_captures(_rotating())
    assert f["detection_type"] == "scraping"
    assert f["metadata"]["pattern"] == "credential_rotation"
    assert f["metadata"]["actor"] == "10.7.7.7" and f["metadata"]["actor_type"] == "ip"
    assert f["metadata"]["credential_count"] == 40
    assert alert_actor(f) == "10.7.7.7"
    assert "not attributed to a single user" in f["reason"]


def test_credential_rotation_is_found_by_the_pipeline_too():
    findings = analyze_captured_traffic(_rotating())
    assert [f["metadata"]["pattern"] for f in findings if f["detection_type"] == "scraping"] == ["credential_rotation"]


def test_unrelated_users_behind_one_nat_ip_are_not_rotation():
    assert analyze_credential_rotation_from_captures(_nat_users(6, 4)) == []   # 6 credentials, 24 requests
    assert analyze_credential_rotation_from_captures(_nat_users(9, 4)) == []   # 9 credentials, 36 requests


def test_rotation_needs_enough_credentials():
    nine = _rotating(creds=9)
    many_requests_few_creds = [_rec(f"/api/items/{i}", second=i * 0.5, ip="10.6.6.6", fp=f"fpX{i % 9}")
                               for i in range(60)]
    assert analyze_credential_rotation_from_captures(nine) == []
    assert analyze_credential_rotation_from_captures(many_requests_few_creds) == []


def test_single_credential_scraper_is_scraping_not_rotation():
    scraper = [_rec(f"/api/items/{i}", second=i * 0.5, ip="10.5.5.5", fp="fpONE") for i in range(40)]
    assert analyze_credential_rotation_from_captures(scraper) == []
    (f,) = analyze_scraping_from_captures(scraper)
    assert f["metadata"]["actor"] == "fpONE"


def test_anonymous_scraping_is_not_rotation():
    anon = [_rec(f"/api/items/{i}", second=i * 0.5, ip="10.8.8.8") for i in range(40)]
    assert analyze_credential_rotation_from_captures(anon) == []


def test_rotation_outside_the_live_window_is_not_reported():
    old = _rotating()
    later = T0 + timedelta(hours=1)
    assert analyze_credential_rotation_from_captures(old, now=later) == []


def test_known_false_positive_large_nat_office_is_flagged():
    # KNOWN LIMITATION: 15 users behind one IP, 4 requests each within a minute, look
    # like rotation. The rule cannot tell them apart from a bot rotating credentials.
    dense = [_rec(f"/api/items/{u * 4 + k}", second=(u * 4 + k) * 0.8, ip="10.9.9.9", fp=f"fpUSER{u}")
             for u in range(15) for k in range(4)]  # 60 requests within 48 s
    (f,) = analyze_credential_rotation_from_captures(dense)
    assert f["metadata"]["pattern"] == "credential_rotation"


def test_risk_scores_stay_bounded_and_explained():
    huge = [_rec(f"/admin/export/{i}", second=i * 0.1, method="DELETE") for i in range(500)]
    (f,) = analyze_scraping_from_captures(huge)
    assert 0 <= f["risk_score"] <= 100
    assert sum(f["metadata"]["breakdown"].values()) == f["risk_score"]
    assert f["metadata"]["reasons"]


# --- token replay -------------------------------------------------------------------

def test_concurrent_multi_ip_use_is_replay():
    recs = [_rec("/api/me", second=i * 5, ip=f"10.0.0.{i}", fp="fpT") for i in range(5)]
    (f,) = analyze_token_replay_from_captures(recs)
    assert f["metadata"]["rapid_switch_ips"] == 5 and f["metadata"]["rapid_switches"] == 4
    assert "concurrent use" in f["reason"]


def test_roaming_between_networks_minutes_apart_is_not_replay():
    roam = [_rec("/api/me", second=600 * k + j, ip=f"10.0.0.{k}", fp="fpT") for k in range(4) for j in range(3)]
    assert analyze_token_replay_from_captures(roam) == []
    # Phase 1 behaviour is still available for comparison.
    assert analyze_token_replay_from_captures(roam, rapid_switch_gap_seconds=None)


def test_two_devices_alternating_is_not_replay():
    recs = [_rec("/api/me", second=i * 10, ip=f"10.0.0.{i % 2}", fp="fpT") for i in range(20)]
    assert analyze_token_replay_from_captures(recs) == []


def test_replay_needs_a_credential_fingerprint_not_just_repeated_requests():
    anon = [_rec("/api/me", second=i, ip=f"10.0.1.{i}") for i in range(10)]
    assert analyze_token_replay_from_captures(anon) == []


# --- confirmed BOLA via ownership context ----------------------------------------------

def test_unauthorized_successful_read_is_confirmed_bola():
    recs = [_rec("/shop/orders/2", fp="fpMAL"), _rec("/shop/orders/1", second=5, fp="fpMAL")]
    (f,) = analyze_unauthorized_access_from_captures(recs, OWN)
    assert f["detection_type"] == "bola" and f["endpoint"] == "/shop/orders/{id}"
    assert f["metadata"]["unauthorized_objects"] == 2 and f["metadata"]["source"] == "ownership_context"
    assert f["metadata"]["user_id"] == "mallory"
    assert 0 < f["risk_score"] <= 100 and sum(f["metadata"]["breakdown"].values()) == f["risk_score"]


def test_ip_mapped_actor_and_encoded_ids_are_covered():
    (f,) = analyze_unauthorized_access_from_captures([_rec("/shop/orders/%32", ip="10.0.0.9")], OWN)
    assert f["metadata"]["actor_type"] == "ip"


@pytest.mark.parametrize("rec", [
    _rec("/shop/orders/1", fp="fpALICE"),                  # owner reads own object
    _rec("/shop/orders/2", fp="fpMAL", status=403),        # denied: no data returned
    _rec("/shop/orders/2", fp="fpMAL", status=404),
    _rec("/shop/orders/2", fp="fpUNKNOWN"),                # unmapped actor: no claim
    _rec("/shop/orders/99", fp="fpMAL"),                   # object with no known owner
    _rec("/shop/products/2", fp="fpMAL"),                  # template without ownership data
])
def test_no_false_confirmation(rec):
    assert analyze_unauthorized_access_from_captures([rec], OWN) == []


def test_no_context_means_no_claim():
    assert analyze_unauthorized_access_from_captures([_rec("/shop/orders/2", fp="fpMAL")], None) == []
    assert analyze_unauthorized_access_from_captures([_rec("/shop/orders/2", fp="fpMAL")], {}) == []


def test_enumeration_alone_is_not_reported_as_confirmed():
    probe = [_rec(f"/shop/orders/{i}", second=i, fp="fpMAL", status=404) for i in range(100, 115)]
    kinds = {f["detection_type"] for f in analyze_captured_traffic(probe, ownership=OWN)}
    assert "bola_enumeration" in kinds and "bola" not in kinds  # attempts only: nothing was read


def test_validate_and_load_ownership(tmp_path):
    assert validate_ownership(OWN) == OWN
    for bad in ([], {"resources": []}, {"resources": {"/x/{id}": {"1": 5}}}, {"actors": {"a": 1}}):
        with pytest.raises(ValueError):
            validate_ownership(bad)
    good = tmp_path / "own.json"
    good.write_text(json.dumps(OWN))
    assert load_ownership(good) == OWN
    (tmp_path / "bad.json").write_text("{nope")
    for path in (tmp_path / "bad.json", tmp_path / "missing.json"):
        with pytest.raises(ValueError) as err:
            load_ownership(path)
        assert str(tmp_path) not in str(err.value)


def test_scan_persists_confirmed_bola_alert_without_leaking_tokens(tmp_path):
    db = str(tmp_path / "o.db")
    init_db(db)
    with sqlite3.connect(db) as conn:
        conn.execute("INSERT INTO captured_requests (method, path, status_code, duration_ms, client_ip,"
                     " created_at, actor_fp) VALUES ('GET', '/shop/orders/2', 200, 1.0, '9.9.9.9',"
                     " '2026-10-14 00:00:00', 'fpMAL')")
    client = TestClient(create_app(db_path=db, api_key=KEY, ownership=OWN), headers={"X-Sentinel-Key": KEY})
    assert client.post("/api/scan").json()["created"] == 1
    (alert,) = client.get("/api/alerts").json()["items"]
    assert alert["detection_type"] == "bola" and alert["actor"] == "fpMAL"
    assert client.post("/api/scan").json() == {"findings": 1, "created": 0, "updated": 0, "unchanged": 1}


def test_app_refuses_invalid_ownership_context(tmp_path):
    with pytest.raises(ValueError):
        create_app(db_path=str(tmp_path / "x.db"), ownership={"resources": 5})


def test_rotation_sliding_window_matches_brute_force_reference():
    # Property check with a fixed seed: the two-pointer window must agree with a
    # naive per-window recount on which IPs breach. Timestamps are whole seconds,
    # as stored in the capture table.
    import random
    from collections import Counter as _Counter

    def reference(recs):
        flagged = set()
        for ip in {r["client_ip"] for r in recs}:
            rs = sorted((r for r in recs if r["client_ip"] == ip), key=lambda r: r["_t"])
            for e in range(len(rs)):
                win = [r for r in rs[: e + 1] if r["_t"] >= rs[e]["_t"] - timedelta(seconds=60)]
                fps = _Counter(r["actor_fp"] for r in win)
                if len(win) >= 40 and len(fps) >= 10 and max(fps.values()) <= 10 and len({r["path"] for r in win}) >= 20:
                    flagged.add(ip)
        return flagged

    rng = random.Random(11)
    for _ in range(100):
        recs = []
        for _ in range(rng.randint(60, 200)):
            t = (T0 + timedelta(seconds=rng.uniform(0, rng.choice([60, 120, 600])))).replace(microsecond=0)
            recs.append({"client_ip": rng.choice(["1.1.1.1", "2.2.2.2", "3.3.3.3"]),
                         "actor_fp": f"f{rng.randint(0, rng.choice([12, 30, 200]))}",
                         "path": f"/x/{rng.randint(0, 40)}", "method": "GET", "_t": t,
                         "created_at": t.strftime("%Y-%m-%d %H:%M:%S")})
        got = {f["metadata"]["actor"] for f in analyze_credential_rotation_from_captures(
            [{k: v for k, v in r.items() if k != "_t"} for r in recs], all_windows=True)}
        assert got == reference(recs)
