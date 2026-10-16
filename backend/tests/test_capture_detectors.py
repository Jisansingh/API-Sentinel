"""P2: BOLA-enumeration and token-replay detection from captured traffic only."""

from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.analysis import (
    analyze_captured_traffic,
    analyze_enumeration_from_captures,
    analyze_token_replay_from_captures,
)

T0 = datetime(2026, 10, 14, 0, 0, 0)


def _rec(path, status=200, ip="1.2.3.4", fp=None, second=0, method="GET"):
    return {
        "method": method,
        "path": path,
        "status_code": status,
        "duration_ms": 1.0,
        "client_ip": ip,
        "actor_fp": fp,
        "created_at": (T0 + timedelta(seconds=second)).strftime("%Y-%m-%d %H:%M:%S"),
    }


# --- BOLA enumeration ---------------------------------------------------------

def test_id_probing_with_denials_is_bola_enumeration():
    records = [
        _rec(f"/api/orders/{i}", status=403 if i % 4 else 200, fp="fpA", second=i)
        for i in range(15)
    ]
    findings = analyze_enumeration_from_captures(records)
    assert len(findings) == 1
    f = findings[0]
    assert f["detection_type"] == "bola_enumeration"
    assert f["endpoint"] == "/api/orders/{id}"
    assert f["metadata"]["actor"] == "fpA"
    assert f["metadata"]["actor_type"] == "credential"
    assert f["metadata"]["distinct_ids"] == 15
    assert f["metadata"]["denied_ratio"] >= 0.5
    assert 0 < f["risk_score"] <= 100


def test_bulk_successful_reads_are_not_enumeration():
    """All-200 bulk reads are scraping, not authorization probing."""
    records = [_rec(f"/api/items/{i}", second=i) for i in range(25)]
    assert analyze_enumeration_from_captures(records) == []


def test_few_denials_or_few_ids_do_not_trigger():
    few_ids = [_rec(f"/api/orders/{i % 3}", status=403, second=i) for i in range(20)]
    assert analyze_enumeration_from_captures(few_ids) == []
    old_probe = [_rec(f"/api/orders/{i}", status=404, second=i) for i in range(15)]
    later = [_rec("/api/orders/1", status=200, second=500)]
    # Rolling window: probes older than the burst window no longer count for the burst rule...
    assert analyze_enumeration_from_captures(old_probe + later, detect_low_and_slow=False) == []
    # ...but within the hour they are still a (low-and-slow) probe, and after the hour they expire too.
    (slow,) = analyze_enumeration_from_captures(old_probe + later)
    assert slow["metadata"]["rule_id"] == "BOLA-ENUM-SLOW"
    much_later = [_rec("/api/orders/1", status=200, second=3700)]
    assert analyze_enumeration_from_captures(old_probe + much_later) == []


def test_enumeration_falls_back_to_ip_and_separates_actors():
    a = [_rec(f"/api/orders/{i}", status=404, ip="9.9.9.9", second=i) for i in range(15)]
    b = [_rec(f"/api/orders/{i}", status=404, ip="8.8.8.8", second=i) for i in range(5)]
    findings = analyze_enumeration_from_captures(a + b)
    assert [f["metadata"]["actor"] for f in findings] == ["9.9.9.9"]
    assert findings[0]["metadata"]["actor_type"] == "ip"


# --- Token replay ---------------------------------------------------------------

def test_one_credential_from_many_ips_is_token_replay():
    records = [_rec("/api/me", ip=f"10.0.0.{i}", fp="fpT", second=i * 10) for i in range(5)]
    findings = analyze_token_replay_from_captures(records)
    assert len(findings) == 1
    f = findings[0]
    assert f["detection_type"] == "token_replay"
    assert f["metadata"]["token_fingerprint"] == "fpT"
    assert f["metadata"]["distinct_ips"] == 5
    assert f["metadata"]["source"] == "capture"


def test_token_replay_ignores_few_ips_anonymous_and_old_uses():
    few = [_rec("/api/me", ip=f"10.0.0.{i % 2}", fp="fpT", second=i) for i in range(10)]
    anon = [_rec("/api/me", ip=f"10.0.1.{i}", second=i) for i in range(10)]
    assert analyze_token_replay_from_captures(few + anon) == []
    old = [_rec("/api/me", ip=f"10.0.0.{i}", fp="fpT", second=i) for i in range(5)]
    later = [_rec("/api/me", ip="10.0.0.1", fp="fpT", second=7200)]
    assert analyze_token_replay_from_captures(old + later) == []


# --- Pipeline + HTTP --------------------------------------------------------------

def test_pipeline_includes_capture_detectors():
    probe = [_rec(f"/api/orders/{i}", status=403, fp="fpA", second=i * 7) for i in range(12)]
    # 7s apart: slow enough to stay under the scraping rate limit.
    replay = [_rec("/api/me", ip=f"10.0.0.{i}", fp="fpT", second=i) for i in range(5)]
    types = [f["detection_type"] for f in analyze_captured_traffic(probe + replay)]
    assert types == ["bola_enumeration", "token_replay"]


def test_findings_endpoint_reports_token_replay_from_live_capture(tmp_path, target_app):
    app = target_app(db_path=str(tmp_path / "live.db"), fp_secret="k" * 32)
    for i in range(5):
        client = TestClient(app, client=(f"10.0.0.{i}", 5000))
        client.get("/target/ping", headers={"Authorization": "Bearer stolen-token"})
    body = TestClient(app).get("/api/findings").json()
    replay = [f for f in body["items"] if f["detection_type"] == "token_replay"]
    assert len(replay) == 1
    assert "stolen-token" not in str(body)


# --- Scan-mode scraping over every window -----------------------------------------

def test_all_windows_scraping_matches_rolling_detector_on_current_burst():
    burst = [_rec(f"/api/items/{i}", second=i) for i in range(15)]
    from app.analysis import analyze_scraping_from_captures as scrape
    assert scrape(burst, all_windows=True) == scrape(burst)


def test_all_windows_picks_most_recent_breach_and_ignores_slow_traffic():
    from app.analysis import analyze_scraping_from_captures as scrape
    first = [_rec(f"/api/a/{i}", second=i) for i in range(12)]
    second = [_rec(f"/api/b/{i}", second=600 + i) for i in range(12)]
    quiet = [_rec("/api/c", second=1200)]
    found = scrape(first + second + quiet, all_windows=True)
    assert [f["endpoint"] for f in found] == ["/api/b/{id}"]
    assert found[0]["timestamp"] == (T0 + timedelta(seconds=611)).isoformat()
    slow = [_rec(f"/api/items/{i}", second=i * 7) for i in range(50)]  # ~8.6/min
    assert scrape(slow, all_windows=True) == []
