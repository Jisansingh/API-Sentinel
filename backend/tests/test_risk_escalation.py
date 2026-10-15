"""P4: explainable escalation - magnitude over threshold + endpoint context."""

from datetime import datetime, timedelta

import pytest

from app.analysis import analyze_enumeration_from_captures, analyze_scraping_from_captures
from app.risk_scoring import RiskScorer, guidance

T0 = datetime(2026, 10, 14, 0, 0, 0)


def _base(scorer, detector="scraping"):
    return scorer.calculate_from_detections({detector: {"detected": True, "reason": "r"}})


def test_escalation_tiers_and_breakdown_sums_to_score():
    s = RiskScorer()
    cases = [(1.0, 0), (2.9, 0), (3.0, 10), (6.0, 20), (12.0, 30), (500.0, 30)]
    for ratio, bonus in cases:
        risk = s.escalate(_base(s), magnitude=ratio)
        assert risk.breakdown["magnitude"] == bonus, ratio
        assert risk.score == RiskScorer.SCRAPING_WEIGHT + bonus
        assert sum(risk.breakdown.values()) == risk.score


def test_context_bonus_for_write_methods_and_sensitive_paths():
    s = RiskScorer()
    assert s.escalate(_base(s), method="GET", endpoint="/api/items/{id}").breakdown["context"] == 0
    assert s.escalate(_base(s), method="DELETE", endpoint="/api/items/{id}").breakdown["context"] == 10
    assert s.escalate(_base(s), method="GET", endpoint="/api/admin/export").breakdown["context"] == 10
    # "administrator" is not the "admin" segment: whole segments only.
    assert s.escalate(_base(s), method="GET", endpoint="/api/administrator").breakdown["context"] == 0
    worst = s.escalate(_base(s, "bola"), magnitude=1000, method="POST", endpoint="/internal/x")
    assert worst.score == 35 + 30 + 20 <= 100
    assert any("magnitude" in r for r in worst.reasons)


def _burst(n, path="/api/items/{i}", status=200, step=1, method="GET"):
    return [
        {
            "method": method, "path": path.format(i=i), "status_code": status,
            "duration_ms": 1.0, "client_ip": "1.2.3.4", "actor_fp": None,
            "created_at": (T0 + timedelta(seconds=i * step)).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for i in range(n)
    ]


def test_bigger_scrape_scores_higher_than_barely_over_threshold():
    small = analyze_scraping_from_captures(_burst(15))[0]  # 1.5x rate threshold
    large = analyze_scraping_from_captures(_burst(60))[0]  # 6x
    assert small["risk_score"] == RiskScorer.SCRAPING_WEIGHT
    assert large["risk_score"] == RiskScorer.SCRAPING_WEIGHT + 20
    assert large["metadata"]["breakdown"]["magnitude"] == 20


def test_enumeration_on_sensitive_write_endpoint_scores_higher():
    plain = analyze_enumeration_from_captures(_burst(12, "/api/orders/{i}", 403, step=5))[0]
    admin = analyze_enumeration_from_captures(
        _burst(12, "/api/admin/users/{i}", 403, step=5, method="DELETE"))[0]
    assert plain["risk_score"] == RiskScorer.BOLA_WEIGHT
    assert admin["risk_score"] == RiskScorer.BOLA_WEIGHT + 20
    assert sum(admin["metadata"]["breakdown"].values()) == admin["risk_score"]


def _band_sentences(reasons):
    return [r for r in reasons if r.split(":")[0] in ("Low risk", "Medium risk", "High risk")
            or r.startswith("No suspicious")]


def test_band_sentence_follows_the_final_escalated_score():
    s = RiskScorer()
    cases = [
        # (detector, magnitude, method, endpoint, final score, band)
        ("scraping", 1.0, "GET", "/api/items/{id}", 30, "Low risk"),        # no escalation
        ("scraping", 3.0, "GET", "/api/admin/{id}", 50, "Medium risk"),     # 30 -> 50 crosses Low/Medium
        ("bola", 3.0, "GET", "/shop/admin/{id}", 55, "Medium risk"),        # 35 -> 55 (the demo's confirmed BOLA)
        ("bola", 12.0, "POST", "/internal/x", 85, "High risk"),             # 35 -> 85 crosses into High
    ]
    for detector, mag, method, endpoint, score, band in cases:
        base = _base(s, detector)
        risk = s.escalate(base, magnitude=mag, method=method, endpoint=endpoint)
        assert risk.score == score, (detector, mag)
        # exactly one band sentence, for the final score, and it is last
        assert _band_sentences(risk.reasons) == [risk.reasons[-1]]
        assert risk.reasons[-1].startswith(band), (score, risk.reasons)
        # weights/breakdown/cap unchanged by the reason fix
        assert sum(risk.breakdown.values()) == risk.score <= 100
        assert risk.breakdown[detector] == base.score


def test_escalated_finding_from_the_pipeline_is_not_labelled_low():
    large = analyze_scraping_from_captures(_burst(60))[0]  # 30 + 20 magnitude = 50
    reasons = large["metadata"]["reasons"]
    assert large["risk_score"] == 50
    assert reasons[-1].startswith("Medium risk") and not any(r.startswith("Low risk") for r in reasons)


@pytest.mark.parametrize("score,band", [
    (0, "No suspicious"), (1, "Low risk"), (39, "Low risk"), (40, "Medium risk"),
    (69, "Medium risk"), (70, "High risk"), (100, "High risk"),
])
def test_guidance_band_boundaries(score, band):
    assert guidance(score).startswith(band)
