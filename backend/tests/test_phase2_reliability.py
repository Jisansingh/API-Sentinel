"""Phase 2 reliability: UTC normalization, window boundaries, idle expiry,
path normalization, hidden internal routes, alert time handling."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.analysis import analyze_captured_traffic, parse_created_at
from app.discovery import normalize_path
from app.main import create_app
from app.storage import fetch_captured_requests, init_db, list_alerts, save_captured_request, upsert_alerts
from app.timeutil import parse_timestamp, to_utc_naive

T0 = datetime(2026, 10, 14, 0, 0, 0)
KEY = "a" * 32


def _rec(i, path="/api/items/{i}", at=T0, ip="1.2.3.4", status=200):
    return {"method": "GET", "path": path.format(i=i), "status_code": status, "duration_ms": 1.0,
            "client_ip": ip, "actor_fp": None, "created_at": at.strftime("%Y-%m-%d %H:%M:%S")}


# --- timestamps ---------------------------------------------------------------

def test_timestamps_normalize_to_naive_utc():
    ist = timezone(timedelta(hours=5, minutes=30))
    assert parse_timestamp(datetime(2026, 1, 1, 5, 30, tzinfo=ist)) == datetime(2026, 1, 1, 0, 0)
    assert parse_timestamp("2026-01-01T05:30:00+05:30") == datetime(2026, 1, 1, 0, 0)
    assert parse_timestamp("2026-01-01T00:00:00Z") == datetime(2026, 1, 1, 0, 0)
    assert parse_timestamp("2026-01-01 00:00:00") == datetime(2026, 1, 1, 0, 0)
    assert to_utc_naive(datetime(2026, 1, 1)) == datetime(2026, 1, 1)
    assert parse_created_at("garbage") is None and parse_created_at(None) is None and parse_created_at(7) is None


def test_mixed_naive_and_aware_records_do_not_crash_or_misorder():
    ist = timezone(timedelta(hours=5, minutes=30))
    records = [_rec(i) for i in range(6)]
    # Same instants as the naive ones, written with an offset: must not raise TypeError.
    for i, r in enumerate(records[3:], start=3):
        r["created_at"] = (T0 + timedelta(seconds=i)).replace(tzinfo=timezone.utc).astimezone(ist).isoformat()
    for i, r in enumerate(records[:3]):
        r["created_at"] = (T0 + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")
    burst = [dict(_rec(i), created_at=(T0 + timedelta(seconds=i)).replace(tzinfo=timezone.utc)
                  .astimezone(ist).isoformat() if i % 2 else (T0 + timedelta(seconds=i))
                  .strftime("%Y-%m-%d %H:%M:%S")) for i in range(12)]
    findings = analyze_captured_traffic(burst)
    assert len(findings) == 1 and findings[0]["timestamp"] == (T0 + timedelta(seconds=11)).isoformat()


def test_alert_with_offset_timestamp_is_the_same_instant_not_newer(tmp_path):
    db = str(tmp_path / "a.db")
    init_db(db)
    base = {"detection_type": "scraping", "actor": "1.2.3.4", "endpoint": "/e", "risk_score": 30,
            "reason": "r", "metadata": {}}
    upsert_alerts(db, [{**base, "timestamp": "2026-10-14T00:00:11"}])
    same_instant = "2026-10-14T05:30:11+05:30"
    assert upsert_alerts(db, [{**base, "timestamp": same_instant}]) == {"created": 0, "updated": 0, "unchanged": 1}
    newer = "2026-10-14T05:30:12+05:30"
    assert upsert_alerts(db, [{**base, "timestamp": newer}])["updated"] == 1
    (alert,) = list_alerts(db)
    assert alert["last_seen"] == "2026-10-14T00:00:12" and alert["occurrences"] == 2  # stored as naive UTC


def test_alert_ordering_is_deterministic_for_equal_last_seen(tmp_path):
    db = str(tmp_path / "o.db")
    init_db(db)
    for actor, score in (("a", 30), ("b", 65), ("c", 30)):
        upsert_alerts(db, [{"detection_type": "scraping", "actor": actor, "endpoint": "/e",
                            "risk_score": score, "reason": "r", "metadata": {},
                            "timestamp": "2026-10-14T00:00:00"}])
    assert [a["actor"] for a in list_alerts(db)] == ["b", "a", "c"]  # score desc, then id


# --- rolling-window boundaries -----------------------------------------------------

def _distinct(n, step=1.0, start=T0):
    return [dict(_rec(i), created_at=(start + timedelta(seconds=i * step)).strftime("%Y-%m-%d %H:%M:%S"))
            for i in range(n)]


def test_rate_threshold_boundary_is_strictly_greater():
    assert analyze_captured_traffic(_distinct(10)) == []          # == threshold: quiet
    assert len(analyze_captured_traffic(_distinct(11))) == 1       # threshold + 1: flagged


def test_window_edge_is_inclusive_at_exactly_the_window():
    # 11 requests spanning exactly 60 s (first one 60 s before the last) are in-window...
    spanning = _distinct(11, step=6.0)
    assert len(analyze_captured_traffic(spanning)) == 1
    # ...but if the span is 60.0 s + 1 s the oldest request falls out and only 10 remain.
    spanning[0]["created_at"] = (T0 - timedelta(seconds=1)).strftime("%Y-%m-%d %H:%M:%S")
    assert analyze_captured_traffic(spanning) == []


def test_idle_actor_expires_only_when_a_clock_is_given():
    records = _distinct(15)
    assert len(analyze_captured_traffic(records)) == 1  # legacy: anchored at last request
    inside = analyze_captured_traffic(records, now=T0 + timedelta(seconds=30))
    assert len(inside) == 1
    assert analyze_captured_traffic(records, now=T0 + timedelta(minutes=10)) == []  # idle: gone


def test_findings_endpoint_uses_injected_clock_and_scan_keeps_history(tmp_path):
    db = str(tmp_path / "c.db")
    init_db(db)
    with sqlite3.connect(db) as conn:
        for r in _distinct(15):
            conn.execute("INSERT INTO captured_requests (method, path, status_code, duration_ms, client_ip,"
                         " created_at) VALUES ('GET', ?, 200, 1.0, '1.2.3.4', ?)", (r["path"], r["created_at"]))
    now = {"t": T0 + timedelta(seconds=20)}
    client = TestClient(create_app(db_path=db, api_key=KEY, clock=lambda: now["t"]),
                        headers={"X-Sentinel-Key": KEY})
    assert client.get("/api/findings").json()["total_findings"] == 1
    now["t"] = T0 + timedelta(hours=2)
    assert client.get("/api/findings").json()["total_findings"] == 0  # live view expired
    assert client.post("/api/scan").json()["created"] == 1             # scan still finds the old burst
    assert client.get("/api/alerts").json()["total"] == 1


def test_delayed_out_of_order_rows_are_sorted_by_time_not_id(tmp_path):
    shuffled = list(reversed(_distinct(15)))
    assert len(analyze_captured_traffic(shuffled)) == 1


# --- path normalization ---------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("/users/%31%30", "/users/{id}"),
    ("//users///5/", "/users/{id}"),
    ("/a/../users/5", "/users/{id}"),
    ("/users/./5?x=1", "/users/{id}"),
    ("/users/%35", "/users/{id}"),
    ("/users/٣", "/users/٣"),                 # non-ASCII digits are not IDs
    ("/files/a%2Fb", "/files/a%2Fb"),          # encoded slash stays one segment
    ("/users/search", "/users/search"),
    ("/", "/"),
    ("", "/"),
    ("/x/123e4567-e89b-12d3-a456-426614174000/", "/x/{id}"),
])
def test_normalize_path_edge_cases(raw, expected):
    assert normalize_path(raw) == expected


def test_encoded_ids_are_counted_as_distinct_objects_by_enumeration():
    recs = [dict(_rec(i, path="/api/orders/" + "".join(f"%{ord(c):02X}" for c in str(i)), status=404),
                 created_at=(T0 + timedelta(seconds=i)).strftime("%Y-%m-%d %H:%M:%S")) for i in range(12)]
    kinds = {f["detection_type"] for f in analyze_captured_traffic(recs)}
    assert "bola_enumeration" in kinds  # encoding the ID does not hide the pattern


# --- historical internal-route rows are hidden, never deleted -----------------------------

def test_historical_internal_rows_are_hidden_but_kept(tmp_path):
    db = str(tmp_path / "h.db")
    init_db(db)
    for path in ("/docs", "/openapi.json", "/redoc", "/docs/oauth2-redirect", "/api/real"):
        save_captured_request(db, method="GET", path=path, status_code=200, duration_ms=1.0, client_ip="t")
    client = TestClient(create_app(db_path=db))
    assert [i["path"] for i in client.get("/api/inventory").json()["items"]] == ["/api/real"]
    shadow = client.get("/api/shadow-apis").json()
    assert [s["path"] for s in shadow["shadow_apis"]] == ["/api/real"]
    assert len(fetch_captured_requests(db, include_internal=True)) == 5  # history intact
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()[0] == 5


def test_injected_created_at_is_stored_verbatim(tmp_path):
    db = str(tmp_path / "t.db")
    init_db(db)
    save_captured_request(db, method="GET", path="/a", status_code=200, duration_ms=1.0, client_ip="t",
                          created_at="2026-01-02 03:04:05")
    assert fetch_captured_requests(db)[0]["created_at"] == "2026-01-02 03:04:05"
