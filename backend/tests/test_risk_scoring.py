"""
Tests for risk scoring module.

Tests verify score calculation, determinism, and no double-counting.
"""

import pytest
from app.risk_scoring import RiskScorer, RiskScore


class TestRiskScorer:
    """Tests for risk score calculation."""

    def test_no_detections_zero_score(self):
        """No detections should result in score of 0."""
        scorer = RiskScorer()

        result = scorer.calculate_score()

        assert result.score == 0
        assert "No suspicious" in result.reasons[0]

    def test_bola_only_detection(self):
        """BOLA detection alone should set score to BOLA_WEIGHT."""
        scorer = RiskScorer()

        result = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Unauthorized access to resource"
        )

        assert result.score == scorer.BOLA_WEIGHT
        assert result.breakdown["bola"] == scorer.BOLA_WEIGHT
        assert result.breakdown["scraping"] == 0
        assert result.breakdown["token_replay"] == 0
        assert any("BOLA" in r for r in result.reasons)

    def test_scraping_only_detection(self):
        """Scraping detection alone should set score to SCRAPING_WEIGHT."""
        scorer = RiskScorer()

        result = scorer.calculate_score(
            scraping_detected=True,
            scraping_reason="50 requests in 60 seconds"
        )

        assert result.score == scorer.SCRAPING_WEIGHT
        assert result.breakdown["scraping"] == scorer.SCRAPING_WEIGHT
        assert result.breakdown["bola"] == 0
        assert result.breakdown["token_replay"] == 0
        assert any("scraping" in r.lower() for r in result.reasons)

    def test_token_replay_only_detection(self):
        """Token replay detection alone should set score to TOKEN_REPLAY_WEIGHT."""
        scorer = RiskScorer()

        result = scorer.calculate_score(
            token_replay_detected=True,
            token_replay_reason="Token used from 5 different IPs"
        )

        assert result.score == scorer.TOKEN_REPLAY_WEIGHT
        assert result.breakdown["token_replay"] == scorer.TOKEN_REPLAY_WEIGHT
        assert result.breakdown["bola"] == 0
        assert result.breakdown["scraping"] == 0
        assert any("token" in r.lower() for r in result.reasons)

    def test_all_detections_add_up(self):
        """All detections should add up without exceeding 100."""
        scorer = RiskScorer()

        result = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Unauthorized access",
            scraping_detected=True,
            scraping_reason="High request rate",
            token_replay_detected=True,
            token_replay_reason="Token used from multiple IPs"
        )

        expected_score = (
            scorer.BOLA_WEIGHT +
            scorer.SCRAPING_WEIGHT +
            scorer.TOKEN_REPLAY_WEIGHT
        )

        # Score should not exceed 100
        assert result.score <= 100
        assert result.breakdown["bola"] == scorer.BOLA_WEIGHT
        assert result.breakdown["scraping"] == scorer.SCRAPING_WEIGHT
        assert result.breakdown["token_replay"] == scorer.TOKEN_REPLAY_WEIGHT
        assert len(result.reasons) >= 3  # At least one per detection

    def test_score_deterministic(self):
        """Score calculation should be deterministic."""
        scorer = RiskScorer()

        result1 = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test",
            scraping_detected=True,
            scraping_reason="Test"
        )

        result2 = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test",
            scraping_detected=True,
            scraping_reason="Test"
        )

        assert result1.score == result2.score
        assert result1.breakdown == result2.breakdown

    def test_score_capped_at_100(self):
        """Score should never exceed 100 even with high weights."""
        scorer = RiskScorer()

        # Set weights very high
        scorer.BOLA_WEIGHT = 50
        scorer.SCRAPING_WEIGHT = 50
        scorer.TOKEN_REPLAY_WEIGHT = 50

        result = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test",
            scraping_detected=True,
            scraping_reason="Test",
            token_replay_detected=True,
            token_replay_reason="Test"
        )

        assert result.score == 100

    def test_score_ranges_categorized(self):
        """Score ranges should be categorized correctly."""
        scorer = RiskScorer()

        # Low risk
        result_low = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test"
        )
        assert result_low.score < 40
        assert "low" in result_low.reasons[-1].lower()

        # Medium risk
        result_medium = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test",
            scraping_detected=True,
            scraping_reason="Test"
        )
        assert 40 <= result_medium.score < 70
        assert "medium" in result_medium.reasons[-1].lower()

        # High risk
        result_high = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test",
            scraping_detected=True,
            scraping_reason="Test",
            token_replay_detected=True,
            token_replay_reason="Test"
        )
        assert result_high.score >= 70
        assert "high" in result_high.reasons[-1].lower()

    def test_no_double_counting(self):
        """Each signal should be counted exactly once."""
        scorer = RiskScorer()

        # Same detection twice should not double-count
        result = scorer.calculate_score(
            bola_detected=True,
            bola_reason="Test"
        )

        # Breakdown should show only one BOLA weight, not double
        total = (
            result.breakdown["bola"] +
            result.breakdown["scraping"] +
            result.breakdown["token_replay"]
        )

        assert total == result.score
        assert result.breakdown["bola"] == scorer.BOLA_WEIGHT


class TestCalculateFromDetections:
    """Tests for calculate_from_detections method."""

    def test_empty_detections_dict(self):
        """Empty detections dict should result in score 0."""
        scorer = RiskScorer()

        result = scorer.calculate_from_detections({})

        assert result.score == 0

    def test_detections_dict_format(self):
        """Should handle standard detections dictionary format."""
        scorer = RiskScorer()

        detections = {
            "bola": {"detected": True, "reason": "Unauthorized access"},
            "scraping": {"detected": False, "reason": ""},
            "token_replay": {"detected": True, "reason": "Multi-IP usage"}
        }

        result = scorer.calculate_from_detections(detections)

        assert result.score == scorer.BOLA_WEIGHT + scorer.TOKEN_REPLAY_WEIGHT
        assert result.breakdown["bola"] == scorer.BOLA_WEIGHT
        assert result.breakdown["scraping"] == 0
        assert result.breakdown["token_replay"] == scorer.TOKEN_REPLAY_WEIGHT

    def test_partial_detections_dict(self):
        """Should handle partial detections dict (missing keys)."""
        scorer = RiskScorer()

        detections = {
            "bola": {"detected": True, "reason": "Test"}
        }

        result = scorer.calculate_from_detections(detections)

        assert result.score == scorer.BOLA_WEIGHT

    def test_malformed_detections_dict_safe(self):
        """Should handle malformed detections dict gracefully."""
        scorer = RiskScorer()

        detections = {
            "bola": {"detected": True},  # Missing 'reason'
            "scraping": {},  # Missing 'detected'
            "token_replay": None  # Wrong type
        }

        # Should not crash
        result = scorer.calculate_from_detections(detections)

        assert result.score == scorer.BOLA_WEIGHT


class TestRiskScoreDataclass:
    """Tests for RiskScore dataclass."""

    def test_risk_score_creation(self):
        """RiskScore should be creatable with all fields."""
        score = RiskScore(
            score=50,
            reasons=["Test reason 1", "Test reason 2"],
            breakdown={"bola": 35, "scraping": 15, "token_replay": 0}
        )

        assert score.score == 50
        assert len(score.reasons) == 2
        assert score.breakdown["bola"] == 35

    def test_risk_score_immutable_fields(self):
        """RiskScore fields should be accessible."""
        score = RiskScore(
            score=75,
            reasons=["Reason"],
            breakdown={"bola": 35, "scraping": 30, "token_replay": 10}
        )

        assert score.score == 75
        assert "Reason" in score.reasons
        assert score.breakdown["token_replay"] == 10


class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_reason_strings(self):
        """Should handle empty reason strings."""
        scorer = RiskScorer()

        result = scorer.calculate_score(
            bola_detected=True,
            bola_reason="",
            scraping_detected=True,
            scraping_reason=""
        )

        # Should still have reasons from general categories
        assert len(result.reasons) >= 2
        assert result.score > 0

    def test_very_long_reason_strings(self):
        """Should handle very long reason strings."""
        scorer = RiskScorer()
        long_reason = "A" * 1000

        result = scorer.calculate_score(
            bola_detected=True,
            bola_reason=long_reason
        )

        assert long_reason in result.reasons[0]
        assert result.score == scorer.BOLA_WEIGHT
