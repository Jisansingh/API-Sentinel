from datetime import datetime, timedelta

from app.runtime_monitor import build_runtime_baselines, fetch_runtime_records
from app.storage import init_db, save_captured_request


def test_runtime_baseline_tracks_request_size_status_and_caller():
    now = datetime(2026, 10, 16, 12, 30)
    records = [
        {"method": "POST", "path": "/users/123", "status_code": 201,
         "created_at": (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"),
         "payload_bytes": 120, "client_ip": "127.0.0.1", "actor_fp": "abc"},
        {"method": "POST", "path": "/users/456", "status_code": 500,
         "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
         "payload_bytes": 240, "client_ip": "127.0.0.1", "actor_fp": "abc"},
    ]
    result = build_runtime_baselines(records, now=now, days=30)
    assert result["requests_analyzed"] == 2
    endpoint = result["endpoints"][0]
    assert endpoint["endpoint"] == "POST /users/{id}"
    assert endpoint["payload_bytes_max"] == 240
    assert endpoint["server_error_rate"] == 0.5
    assert endpoint["current_hour_requests"] == 1
    assert result["callers"][0]["caller"] == "credential:abc"


def test_rate_spike_is_not_alerted_without_matching_history():
    now = datetime(2026, 10, 16, 12, 30)
    records = [{"method": "GET", "path": "/items", "status_code": 200,
                "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                "payload_bytes": 0, "client_ip": "127.0.0.1"} for _ in range(20)]
    result = build_runtime_baselines(records, now=now, days=30)
    endpoint = result["endpoints"][0]
    assert endpoint["rate_anomaly"] is False
    assert endpoint["rate_alert_suppressed_reason"] == "insufficient matching historical buckets"


def test_peak_comparison_uses_same_weekday_and_hour():
    now = datetime(2026, 10, 16, 12, 30)  # Friday
    records = []
    # Six prior Fridays at the same hour establish a baseline of 10 requests.
    for weeks_ago in range(1, 7):
        hour = now.replace(minute=0, second=0) - timedelta(days=7 * weeks_ago)
        for _ in range(10):
            records.append({"method": "GET", "path": "/items", "status_code": 200,
                           "created_at": hour.strftime("%Y-%m-%d %H:%M:%S"),
                           "payload_bytes": 50, "client_ip": "127.0.0.1"})
    # Current hour is higher, but same-slot median remains the baseline.
    for _ in range(12):
        records.append({"method": "GET", "path": "/items", "status_code": 200,
                       "created_at": now.strftime("%Y-%m-%d %H:%M:%S"),
                       "payload_bytes": 50, "client_ip": "127.0.0.1"})
    result = build_runtime_baselines(records, now=now, days=60)
    endpoint = result["endpoints"][0]
    assert endpoint["baseline_median_requests"] == 10
    assert endpoint["rate_anomaly"] is False


def test_self_route_exclusion_from_baselines(tmp_path):
    """Regression: historical internal /api/* and doc-route rows must not
    pollute runtime baseline calculations (they are dashboard polling, not
    monitored API traffic).  The rows stay in the database."""
    db = str(tmp_path / "base.db")
    init_db(db)
    now = datetime(2026, 10, 16, 12, 0)
    ts = now.strftime("%Y-%m-%d %H:%M:%S")
    # 31 internal/self-route requests (the known issue)
    self_paths = [
        "/api/health", "/api/inventory", "/api/findings", "/api/alerts",
        "/api/shadow-apis", "/api/scan", "/api/rate-limits", "/api/gateway-events",
        "/api/evaluation", "/api/source-scan", "/api/source-scan/upload",
        "/api/source-apis", "/api/runtime/baselines",
        "/docs", "/redoc", "/openapi.json",
    ]
    for p in self_paths:
        save_captured_request(db, method="GET", path=p, status_code=200,
                              duration_ms=1.0, client_ip="127.0.0.1", created_at=ts)
        save_captured_request(db, method="GET", path=p, status_code=200,
                              duration_ms=1.0, client_ip="127.0.0.1", created_at=ts)
    # 5 real monitored-traffic requests
    for i in range(5):
        save_captured_request(db, method="GET", path=f"/shop/products/{i+1}",
                              status_code=200, duration_ms=2.0, client_ip="10.0.0.1",
                              created_at=ts)

    # Default: self-routes excluded
    records = fetch_runtime_records(db)
    assert len(records) == 5
    assert all("/shop/" in r["path"] for r in records)

    # include_internal: everything
    all_records = fetch_runtime_records(db, include_internal=True)
    assert len(all_records) == 5 + 2 * len(self_paths)

    # Baseline calculation on filtered records sees only the shop endpoint
    result = build_runtime_baselines(records, now=now, days=30)
    assert result["requests_analyzed"] == 5
    endpoints = [e["endpoint"] for e in result["endpoints"]]
    assert "GET /shop/products/{id}" in endpoints
    # No /api/* or /docs routes in the output
    for ep in endpoints:
        assert not ep.startswith("GET /api/")
        assert not ep.startswith("GET /docs")
        assert not ep.startswith("GET /openapi")
