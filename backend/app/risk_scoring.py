"""
Risk scoring module.

Calculates a composite risk score (0-100) from detected abuse patterns.
Scoring is deterministic and avoids double-counting signals.
"""

from dataclasses import dataclass
from typing import List, Dict, Any


@dataclass
class RiskScore:
    """Risk assessment result.

    Attributes:
        score: Composite risk score from 0 (safe) to 100 (critical).
        reasons: List of human-readable reasons for the score.
        breakdown: Detailed scores by category (BOLA, scraping, token_replay).
    """
    score: int
    reasons: List[str]
    breakdown: Dict[str, int]


class RiskScorer:
    """Calculates composite risk scores from security signals."""

    # Risk contribution for each signal (should sum to 100 at max)
    BOLA_WEIGHT = 35
    SCRAPING_WEIGHT = 30
    TOKEN_REPLAY_WEIGHT = 35

    def calculate_score(
        self,
        bola_detected: bool = False,
        bola_reason: str = "",
        scraping_detected: bool = False,
        scraping_reason: str = "",
        token_replay_detected: bool = False,
        token_replay_reason: str = ""
    ) -> RiskScore:
        """Calculate composite risk score.

        Each signal is scored independently. Multiple signals add up to higher risk.
        Maximum possible score is 100 (all three threats detected).

        Args:
            bola_detected: Whether BOLA vulnerability was detected.
            bola_reason: Reason string if BOLA detected.
            scraping_detected: Whether scraping pattern was detected.
            scraping_reason: Reason string if scraping detected.
            token_replay_detected: Whether token replay was detected.
            token_replay_reason: Reason string if token replay detected.

        Returns:
            RiskScore with composite score (0-100), reasons, and breakdown.
        """
        score = 0
        reasons = []
        breakdown = {
            "bola": 0,
            "scraping": 0,
            "token_replay": 0
        }

        # BOLA: Critical threat (high weight)
        if bola_detected:
            score += self.BOLA_WEIGHT
            breakdown["bola"] = self.BOLA_WEIGHT
            reasons.append(f"BOLA detected: {bola_reason}")

        # Scraping: High volume abuse (moderate weight)
        if scraping_detected:
            score += self.SCRAPING_WEIGHT
            breakdown["scraping"] = self.SCRAPING_WEIGHT
            reasons.append(f"Scraping detected: {scraping_reason}")

        # Token replay: Authentication bypass (high weight)
        if token_replay_detected:
            score += self.TOKEN_REPLAY_WEIGHT
            breakdown["token_replay"] = self.TOKEN_REPLAY_WEIGHT
            reasons.append(f"Token replay detected: {token_replay_reason}")

        # Cap score at 100
        final_score = min(score, 100)

        # Add general guidance based on score
        if final_score == 0:
            reasons.append("No suspicious patterns detected.")
        elif final_score < 40:
            reasons.append("Low risk: minor anomalies detected.")
        elif final_score < 70:
            reasons.append("Medium risk: multiple threat patterns detected.")
        else:
            reasons.append("High risk: critical threat patterns detected.")

        return RiskScore(
            score=final_score,
            reasons=reasons,
            breakdown=breakdown
        )

    def calculate_from_detections(
        self,
        detections: Dict[str, Dict[str, Any]]
    ) -> RiskScore:
        """Calculate risk score from a detections dictionary.

        Expected format:
        {
            "bola": {"detected": bool, "reason": str},
            "scraping": {"detected": bool, "reason": str},
            "token_replay": {"detected": bool, "reason": str}
        }

        Args:
            detections: Dictionary with detection results.

        Returns:
            RiskScore object.
        """
        def safe_get(key):
            val = detections.get(key, {})
            return val if val is not None else {}

        return self.calculate_score(
            bola_detected=safe_get("bola").get("detected", False),
            bola_reason=safe_get("bola").get("reason", ""),
            scraping_detected=safe_get("scraping").get("detected", False),
            scraping_reason=safe_get("scraping").get("reason", ""),
            token_replay_detected=safe_get("token_replay").get("detected", False),
            token_replay_reason=safe_get("token_replay").get("reason", "")
        )
