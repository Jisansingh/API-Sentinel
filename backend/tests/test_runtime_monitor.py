from datetime import datetime, timedelta

from app.runtime_monitor import build_runtime_baselines


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
