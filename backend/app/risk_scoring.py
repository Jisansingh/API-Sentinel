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


# (exclusive upper bound, band sentence); the sentence for the *final* score is
# always the last entry of RiskScore.reasons.
GUIDANCE = (
    (1, "No suspicious patterns detected."),
    (40, "Low risk: minor anomalies detected."),
    (70, "Medium risk: significant threat patterns detected."),
    (float("inf"), "High risk: critical threat patterns detected."),
)


def guidance(score: int) -> str:
    """0 = none, 1-39 low, 40-69 medium, 70-100 high."""
    return next(text for limit, text in GUIDANCE if score < limit)


class RiskScorer:
    """Calculates composite risk scores from security signals."""

    # Risk contribution for each signal (should sum to 100 at max)
    BOLA_WEIGHT = 35
    SCRAPING_WEIGHT = 30
    TOKEN_REPLAY_WEIGHT = 35

    # Escalation (see escalate): (observed/threshold ratio, bonus points).
    # Below 3x a finding keeps its base weight.
    MAGNITUDE_TIERS = ((12.0, 30), (6.0, 20), (3.0, 10))
    CONTEXT_POINTS = 10
    WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    SENSITIVE_SEGMENTS = frozenset({"admin", "internal", "export", "debug"})

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

        reasons.append(guidance(final_score))

        return RiskScore(
            score=final_score,
            reasons=reasons,
            breakdown=breakdown
        )

    def escalate(
        self,
        risk: RiskScore,
        magnitude: float = 1.0,
        method: str = "",
        endpoint: str = "",
    ) -> RiskScore:
        """Add explainable bonuses to a single-signal score.

        ``magnitude`` is observed/threshold (e.g. 60 requests vs 10 = 6.0).
        Bonuses land in separate ``magnitude`` / ``context`` breakdown keys,
        so the detector keys keep their base weight and every breakdown
        value still sums to the score.
        """
        mag = next((pts for ratio, pts in self.MAGNITUDE_TIERS if magnitude >= ratio), 0)
        segments = {seg.lower() for seg in endpoint.split("/") if seg}
        ctx = self.CONTEXT_POINTS * (
            (method.upper() in self.WRITE_METHODS) + bool(segments & self.SENSITIVE_SEGMENTS)
        )
        # The band sentence of the base score is replaced by one for the final score.
        band_texts = {text for _, text in GUIDANCE}
        reasons = [r for r in risk.reasons if r not in band_texts]
        if mag:
            reasons.append(f"+{mag} magnitude: {magnitude:.1f}x over threshold")
        if ctx:
            reasons.append(f"+{ctx} context: write method and/or sensitive endpoint")
        breakdown = {**risk.breakdown, "magnitude": mag, "context": ctx}
        score = min(100, sum(breakdown.values()))
        return RiskScore(score=score, reasons=[*reasons, guidance(score)], breakdown=breakdown)

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
