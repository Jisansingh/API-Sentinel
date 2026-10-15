# Security Detection Contract

This document defines the interfaces between the security detection modules and the rest of the API Sentinel backend.

## Overview

The security pipeline contains three independent threat detectors:
1. **BOLA (Broken Object-Level Authorization)** — detects unauthorized resource access
2. **Scraping** — detects high-volume request patterns
3. **Token Replay** — detects token misuse and geographic anomalies

A **Risk Scorer** combines signals into a single 0-100 score.

## Abuse Detection Module

File: `backend/app/abuse_detection.py`

### BOLA Detector

Detects when a user accesses a resource they are not authorized for.

**Function Signature:**
```python
BOLADetector.detect(
    user_id: str,
    resource_id: str,
    authorized_resource_ids: Set[str]
) -> Tuple[bool, str]
```

**Arguments:**
- `user_id` — Username or unique user identifier (string)
- `resource_id` — The resource being accessed (string)
- `authorized_resource_ids` — Set of resource IDs this user is allowed to access

**Returns:**
- Tuple of (is_bola, reason_string)
  - `is_bola` — True if unauthorized access detected
  - `reason_string` — Human-readable explanation (empty if no violation)

**Example:**
```python
detector = BOLADetector()
authorized = {"doc_1", "doc_2", "doc_3"}
is_bola, reason = detector.detect("user_123", "doc_99", authorized)
# Returns (True, "User user_123 accessed unauthorized resource doc_99")
```

### Scraping Detector

Detects high-volume request patterns (rate or distinct objects).

**Constructor:**
```python
ScrapingDetector()
```

**Method: record_request**
```python
detector.record_request(
    user_id: str,
    object_id: str,
    timestamp: datetime
)
```

**Method: detect**
```python
detector.detect(
    user_id: str,
    time_window_seconds: int = 60,
    rate_threshold: int = 10,
    distinct_threshold: int = 20
) -> Tuple[bool, str]
```

**Arguments:**
- `user_id` — Username or unique identifier (string)
- `time_window_seconds` — Seconds to analyze (default: 60)
- `rate_threshold` — Max requests per window (default: 10)
- `distinct_threshold` — Max unique objects per window (default: 20)

**Returns:**
- Tuple of (is_scraping, reason_string)
  - `is_scraping` — True if scraping pattern detected
  - `reason_string` — Details of which threshold was exceeded

**Maintenance:**
```python
detector.clear_old_history(max_age_hours=24)  # Remove old records
```

**Example:**
```python
detector = ScrapingDetector()
for req in requests:
    detector.record_request(user_id, obj_id, req.timestamp)

is_scraping, reason = detector.detect("user_200", time_window_seconds=60)
# Returns (True, "User user_200 accessed 25 distinct objects in 60s (threshold: 20)")
```

### Token Replay Detector

Detects token misuse (used by multiple users, from many IPs, etc.).

**Constructor:**
```python
TokenReplayDetector()
```

**Static Method: fingerprint_token**
```python
@staticmethod
TokenReplayDetector.fingerprint_token(token: str) -> str
```

Creates a safe fingerprint of a token. **Never stores the raw token.**

Returns a 16-character hex fingerprint (truncated SHA256).

**Method: record_token_use**
```python
detector.record_token_use(
    token: str,
    user_id: str,
    ip_address: str,
    timestamp: datetime
)
```

**Method: detect**
```python
detector.detect(
    token: str,
    user_id: str,
    ip_address: str,
    timestamp: datetime,
    max_ip_changes: int = 3
) -> Tuple[bool, str]
```

**Arguments:**
- `token` — The token string (will be fingerprinted, not stored)
- `user_id` — Expected user for this token
- `ip_address` — IP address of current request
- `timestamp` — Current request timestamp
- `max_ip_changes` — Max unique IPs token can originate from (default: 3)

**Returns:**
- Tuple of (is_replay, reason_string)
  - `is_replay` — True if replay/misuse detected
  - `reason_string` — Details of the violation

**Maintenance:**
```python
detector.clear_old_usage(max_age_hours=24)  # Remove old token data
```

**Example:**
```python
detector = TokenReplayDetector()
detector.record_token_use(token, "user_1", "192.168.1.1", now)
detector.record_token_use(token, "user_2", "192.168.1.2", now + 1min)

is_replay, reason = detector.detect(token, "user_3", "192.168.1.3", now + 2min)
# Returns (True, "Token fingerprint used by multiple users: {'user_1', 'user_2', 'user_3'}")
```

---

## Risk Scoring Module

File: `backend/app/risk_scoring.py`

### Risk Scorer

Combines abuse detection signals into a composite 0-100 risk score.

**Constructor:**
```python
RiskScorer()
```

**Attributes (configurable weights):**
- `BOLA_WEIGHT` = 35 (0-35 points)
- `SCRAPING_WEIGHT` = 30 (0-30 points)
- `TOKEN_REPLAY_WEIGHT` = 35 (0-35 points)

**Method: calculate_score**
```python
scorer.calculate_score(
    bola_detected: bool = False,
    bola_reason: str = "",
    scraping_detected: bool = False,
    scraping_reason: str = "",
    token_replay_detected: bool = False,
    token_replay_reason: str = ""
) -> RiskScore
```

**Returns: RiskScore object with:**
- `score` — Integer from 0 to 100
- `reasons` — List of human-readable explanation strings
- `breakdown` — Dict with per-threat scores: `{"bola": int, "scraping": int, "token_replay": int}`

**Score Interpretation:**
- 0 — No threats detected
- 1–39 — Low risk (minor anomalies)
- 40–69 — Medium risk (significant threats)
- 70–100 — High risk (critical threats)

The band is chosen from the **final** score (after any magnitude/context bonuses from `escalate()`), and its sentence is always the last entry of `reasons`. After `escalate()`, `breakdown` also carries `magnitude` and `context` keys and still sums to `score` (cap 100).

**Method: calculate_from_detections**
```python
scorer.calculate_from_detections(detections: Dict) -> RiskScore
```

Convenience method that takes a detections dictionary:
```python
detections = {
    "bola": {"detected": bool, "reason": str},
    "scraping": {"detected": bool, "reason": str},
    "token_replay": {"detected": bool, "reason": str}
}
```

**Example:**
```python
scorer = RiskScorer()

result = scorer.calculate_score(
    bola_detected=True,
    bola_reason="User accessed unauthorized resource",
    scraping_detected=False,
    token_replay_detected=True,
    token_replay_reason="Token used from 5 different IPs"
)

print(f"Risk Score: {result.score}/100")
print(f"Breakdown: {result.breakdown}")
# Output: Risk Score: 70/100
# Breakdown: {'bola': 35, 'scraping': 0, 'token_replay': 35}
```

---

## Integration Points

### Incoming Data

Modules expect:
- Request objects with: `user_id`, `resource_id`, `timestamp`, `token`, `ip_address`
- Authorization context: mapping of user_id → authorized resource IDs
- Request history: timestamped sequence of (user, object, timestamp) tuples

### Outgoing Data

Modules provide:
- Detection results: (is_threat: bool, reason: str) tuples
- Risk scores: RiskScore objects with score (0-100) and explanations
- Breakdown by threat type for granular analysis

### Memory Management

All detectors must periodically clean old data to prevent unbounded growth:
```python
scraping_detector.clear_old_history(max_age_hours=24)
token_detector.clear_old_usage(max_age_hours=24)
```

Recommended: Call daily or when database size exceeds threshold.

---

## Security Notes

- **Never log or store raw tokens.** Use `TokenReplayDetector.fingerprint_token()` only.
- **Fingerprints are short.** Do not rely on them for token validation—use for abuse detection only.
- **Authorization context must come from the app's auth layer,** not from the request itself.
- **Request timestamps should be server-generated,** not client-provided.

---

## Testing

Tests are in `backend/tests/`:
- `test_abuse_detection.py` — BOLA, scraping, token replay tests
- `test_risk_scoring.py` — Risk score calculation and composition tests

Run tests:
```bash
cd backend
python -m pytest tests/ -v
```
