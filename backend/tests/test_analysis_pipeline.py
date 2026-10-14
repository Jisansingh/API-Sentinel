"""Analysis pipeline tests: detectors + risk scoring over explicit/captured data."""

from datetime import datetime, timedelta

from app.abuse_detection import TokenReplayDetector
from app.analysis import (
    analyze_bola_cases,
    analyze_captured_traffic,
    analyze_token_replay_cases,
    parse_created_at,
)
from app.risk_scoring import RiskScorer


def _capture(n, ip="1.2.3.4", base=None):
    base = base or datetime(2026, 10, 14, 0, 0, 0)
    return [
        {
            "method": "GET",
            "path": f"/api/items/{i}",
            "status_code": 200,
            "duration_ms": 1.0,
            "client_ip": ip,
            "created_at": (base + timedelta(seconds=i * 2)).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for i in range(n)
    ]


# --- Empty / malformed inputs ------------------------------------------------

def test_empty_inputs_produce_no_findings():
    assert analyze_captured_traffic([]) == []
    assert analyze_captured_traffic(None) == []  # type: ignore[arg-type]
    assert analyze_bola_cases([]) == []
    assert analyze_token_replay_cases([], []) == []


def test_malformed_capture_records_are_skipped_without_crashing():
    records = [
        None,
        {},
        {"method": "GET"},  # no path/timestamp
        {"path": "/x", "created_at": "not-a-date"},
        {"path": "/x", "created_at": ""},
        {"path": "/x", "created_at": None},
    ]
    assert analyze_captured_traffic(records) == []  # type: ignore[list-item]


def test_incomplete_bola_and_token_cases_are_skipped():
    assert analyze_bola_cases([{"user_id": "u"}]) == []
    assert analyze_bola_cases([{"user_id": "u", "resource_id": "r"}]) == []
    assert analyze_bola_cases(None or []) == []
    now = datetime(2026, 10, 14, 0, 0, 0)
    assert analyze_token_replay_cases(
        [{"token": "t"}], [{"token": "t", "user_id": "u"}]
    ) == []
    assert analyze_token_replay_cases(
        [],
        [{"token": "t", "user_id": "u", "ip_address": "1.1.1.1", "timestamp": now}],
    ) == []  # single normal use: no finding


def test_parse_created_at_handles_shapes():
    assert parse_created_at(None) is None
    assert parse_created_at("") is None
    assert parse_created_at("garbage") is None
    assert parse_created_at(123) is None  # type: ignore[arg-type]
    dt = datetime(2026, 10, 14, 0, 0, 0)
    assert parse_created_at(dt) == dt
    assert parse_created_at("2026-10-14 00:00:00") == dt
    assert parse_created_at("2026-10-14T00:00:00") == dt


# --- Normal traffic ----------------------------------------------------------

def test_normal_capture_volume_produces_no_findings():
    assert analyze_captured_traffic(_capture(3)) == []


def test_authorized_bola_case_produces_no_finding():
    cases = [
        {
            "user_id": "alice",
            "resource_id": "doc_1",
            "authorized_resource_ids": {"doc_1", "doc_2"},
            "endpoint": "/api/docs/doc_1",
        }
    ]
    assert analyze_bola_cases(cases) == []


def test_single_token_use_produces_no_finding():
    now = datetime(2026, 10, 14, 0, 0, 0)
    findings = analyze_token_replay_cases(
        [],
        [{"token": "tok", "user_id": "u", "ip_address": "1.1.1.1", "timestamp": now}],
    )
    assert findings == []


# --- Each abuse detector -----------------------------------------------------

def test_bola_unauthorized_access_produces_finding():
    findings = analyze_bola_cases(
        [
            {
                "user_id": "user_123",
                "resource_id": "doc_99",
                "authorized_resource_ids": {"doc_1", "doc_2"},
                "endpoint": "/api/docs/doc_99",
                "timestamp": "2026-10-14 00:00:00",
            }
        ]
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding["detection_type"] == "bola"
    assert finding["endpoint"] == "/api/docs/doc_99"
    assert finding["risk_score"] == RiskScorer.BOLA_WEIGHT
    assert "unauthorized" in finding["reason"].lower()
    assert "doc_99" in finding["reason"]
    assert finding["timestamp"]
    assert finding["metadata"]["user_id"] == "user_123"


def test_scraping_rate_and_distinct_thresholds_are_configurable():
    assert analyze_captured_traffic(_capture(15)) != []  # default rate 10
    assert (
        analyze_captured_traffic(_capture(15), rate_threshold=1000, distinct_threshold=1000)
        == []
    )
    # 25 distinct rapid requests trigger even with a high rate threshold.
    assert (
        analyze_captured_traffic(
            _capture(25), rate_threshold=1000, distinct_threshold=20
        ) != []
    )


def test_token_replay_multi_user_and_multi_ip_produce_findings():
    now = datetime(2026, 10, 14, 0, 0, 0)
    findings = analyze_token_replay_cases(
        [{"token": "secret", "user_id": "u1", "ip_address": "1.1.1.1", "timestamp": now}],
        [{"token": "secret", "user_id": "u2", "ip_address": "1.1.1.2",
          "timestamp": now + timedelta(seconds=10)}],
    )
    assert len(findings) == 1
    assert findings[0]["detection_type"] == "token_replay"
    assert findings[0]["risk_score"] == RiskScorer.TOKEN_REPLAY_WEIGHT


def test_token_fingerprints_never_expose_raw_tokens():
    token = "super-secret-token-value"
    fingerprint = TokenReplayDetector.fingerprint_token(token)
    assert len(fingerprint) == 16
    assert fingerprint != token
    assert TokenReplayDetector.fingerprint_token(token) == fingerprint

    now = datetime(2026, 10, 14, 0, 0, 0)
    findings = analyze_token_replay_cases(
        [
            {"token": token, "user_id": "u1", "ip_address": "1.1.1.1", "timestamp": now},
            {"token": token, "user_id": "u2", "ip_address": "1.1.1.2",
             "timestamp": now + timedelta(seconds=5)},
        ],
        [{"token": token, "user_id": "u3", "ip_address": "1.1.1.3",
          "timestamp": now + timedelta(seconds=10)}],
    )
    assert findings
    blob = str(findings)
    assert token not in blob
    assert findings[0]["metadata"]["token_fingerprint"] == fingerprint


# --- Risk bounds / determinism / no double-counting --------------------------

def test_risk_scores_bounded_deterministic_and_not_double_counted():
    records = _capture(15)
    bola = [
        {"user_id": "u", "resource_id": "r9", "authorized_resource_ids": {"r1"},
         "endpoint": "/api/r/r9", "timestamp": "2026-10-14 00:00:00"}
    ]
    now = datetime(2026, 10, 14, 0, 0, 0)
    token_uses = [
        {"token": "t", "user_id": "u1", "ip_address": "1.1.1.1", "timestamp": now},
        {"token": "t", "user_id": "u2", "ip_address": "1.1.1.2",
         "timestamp": now + timedelta(seconds=5)},
    ]
    token_checks = [
        {"token": "t", "user_id": "u3", "ip_address": "1.1.1.3",
         "timestamp": now + timedelta(seconds=10)}
    ]

    first = analyze_captured_traffic(records, bola_cases=bola,
                                     token_uses=token_uses, token_checks=token_checks)
    second = analyze_captured_traffic(records, bola_cases=bola,
                                      token_uses=token_uses, token_checks=token_checks)
    assert first == second  # deterministic
    assert {f["detection_type"] for f in first} == {"scraping", "bola", "token_replay"}

    for finding in first:
        assert 0 <= finding["risk_score"] <= 100
        breakdown = finding["metadata"]["breakdown"]
        # Breakdown sums exactly to the score: counted once, never doubled.
        assert breakdown["bola"] + breakdown["scraping"] + breakdown["token_replay"] == finding["risk_score"]
    by_type = {f["detection_type"]: f for f in first}
    assert by_type["scraping"]["risk_score"] == RiskScorer.SCRAPING_WEIGHT
    assert by_type["bola"]["risk_score"] == RiskScorer.BOLA_WEIGHT
    assert by_type["token_replay"]["risk_score"] == RiskScorer.TOKEN_REPLAY_WEIGHT


def test_full_pipeline_combines_all_signals_without_invented_data():
    """Capture-only analysis yields scraping; BOLA/token need explicit context."""
    capture_only = analyze_captured_traffic(_capture(15))
    assert [f["detection_type"] for f in capture_only] == ["scraping"]
    # Quiet capture stays quiet even when explicit contexts are empty.
    assert analyze_captured_traffic(_capture(3), bola_cases=[], token_checks=[]) == []


# --- Rolling detection window -------------------------------------------------

def _burst(n, path, method="GET", ip="1.2.3.4", start=None, step=1):
    start = start or datetime(2026, 10, 14, 0, 0, 0)
    return [
        {
            "method": method,
            "path": path,
            "status_code": 200,
            "duration_ms": 1.0,
            "client_ip": ip,
            "created_at": (start + timedelta(seconds=i * step)).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for i in range(n)
    ]


def test_scraping_endpoint_and_method_come_from_active_window_not_history():
    """An old, larger burst must not label a finding triggered by recent traffic."""
    old = _capture(25)  # GET /api/items/{id}, all older than the window below
    recent = _burst(12, "/api/status", method="POST", start=datetime(2026, 10, 14, 0, 10, 0))
    findings = analyze_captured_traffic(old + recent)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["endpoint"] == "/api/status"
    assert finding["metadata"]["method"] == "POST"
    assert finding["metadata"]["request_count"] == 12


def test_scraping_finding_expires_once_burst_leaves_rolling_window():
    """Findings are recalculated per call; a burst older than the window no longer counts."""
    old = _capture(25)
    assert analyze_captured_traffic(old) != []
    later = _burst(3, "/api/health", start=datetime(2026, 10, 14, 0, 5, 0))
    assert analyze_captured_traffic(old + later) == []
