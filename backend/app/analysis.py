"""Integration analysis pipeline: captured traffic -> detectors -> findings.

Connects the discovery side (sanitized capture records from ``app.storage``)
with the security side (``app.abuse_detection`` + ``app.risk_scoring``).

Design decisions (see docs/integration-decisions.md):
- Scraping is the only detector derivable from capture alone. Actor is
  ``client_ip`` (the only identity capture stores), resource is the raw
  path without query string (preserves distinct-object counting; normalized
  paths would collapse /users/1../users/100 into one object and miss
  scraping), timestamp is the server-side ``created_at``.
- BOLA and token replay REQUIRE explicit authorization context / token
  inputs. Captured records contain no user IDs, auth maps, or tokens (by
  design — we never store secrets), so the capture pipeline never invents
  them. Those detectors are exposed here as explicit helper functions that
  take caller-supplied context; with no context they produce no findings
  (safe default, no false positives).
- Each finding carries exactly one detector signal, scored once via
  ``RiskScorer`` (BOLA 35, scraping 30, token-replay 35). No double-counting.
- Findings are sorted deterministically by (detection_type, endpoint).
- Finding timestamps reuse the latest server-observed ``created_at`` among
  the relevant records (deterministic), falling back to UTC now only when
  no timestamp exists.
"""

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from app.abuse_detection import BOLADetector, ScrapingDetector, TokenReplayDetector
from app.discovery import normalize_path
from app.risk_scoring import RiskScorer

DEFAULT_TIME_WINDOW_SECONDS = 60
DEFAULT_RATE_THRESHOLD = 10
DEFAULT_DISTINCT_THRESHOLD = 20
DEFAULT_MAX_IP_CHANGES = 3


def _ensure_timestamp(ts: Any) -> datetime:
    """Ensure a value is a datetime; parse strings or use UTC now."""
    if isinstance(ts, str):
        parsed = parse_created_at(ts)
        return parsed if parsed else datetime.now(timezone.utc)
    if isinstance(ts, datetime):
        return ts
    return datetime.now(timezone.utc)


def parse_created_at(value: Any) -> datetime | None:
    """Parse a ``created_at`` value from storage into a datetime.

    Accepts datetimes (returned as-is), ``YYYY-MM-DD HH:MM:SS`` strings
    (SQLite default), and ISO-8601 strings. Returns None for missing or
    malformed values — callers skip such records instead of failing.
    """
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def raw_path_without_query(path: Any) -> str:
    """Return the path component without query string (safe, no values)."""
    if not isinstance(path, str) or not path:
        return "/"
    return urlsplit(path).path or "/"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _score_single(scorer: RiskScorer, detector: str, reason: str):
    """Score exactly one detector signal (no double-counting)."""
    kwargs: dict[str, Any] = {
        "bola_detected": False,
        "bola_reason": "",
        "scraping_detected": False,
        "scraping_reason": "",
        "token_replay_detected": False,
        "token_replay_reason": "",
    }
    if detector == "bola":
        kwargs["bola_detected"] = True
        kwargs["bola_reason"] = reason
    elif detector == "scraping":
        kwargs["scraping_detected"] = True
        kwargs["scraping_reason"] = reason
    elif detector == "token_replay":
        kwargs["token_replay_detected"] = True
        kwargs["token_replay_reason"] = reason
    return scorer.calculate_score(**kwargs)


def analyze_scraping_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
    rate_threshold: int = DEFAULT_RATE_THRESHOLD,
    distinct_threshold: int = DEFAULT_DISTINCT_THRESHOLD,
) -> list[dict]:
    """Run scraping detection over sanitized capture records.

    Groups by ``client_ip``; feeds each group into ``ScrapingDetector``
    with raw paths as object IDs. Returns finding dicts (unsorted;
    use ``analyze_captured_traffic`` for sorted, scored output).
    Malformed records (missing path/timestamp) are skipped gracefully.
    """
    if scorer is None:
        scorer = RiskScorer()
    if not records:
        return []
    grouped: dict[str, list[tuple[str, datetime, dict]]] = defaultdict(list)
    for rec in records:
        if not isinstance(rec, dict):
            continue
        client_ip = str(rec.get("client_ip") or "unknown")
        raw_path = raw_path_without_query(rec.get("path", "/"))
        ts = parse_created_at(rec.get("created_at"))
        if ts is None:
            continue
        grouped[client_ip].append((raw_path, ts, rec))

    findings: list[dict] = []
    for client_ip in sorted(grouped):
        entries = sorted(grouped[client_ip], key=lambda e: e[1])
        detector = ScrapingDetector()
        for raw_path, ts, _ in entries:
            detector.record_request(client_ip, raw_path, ts)
        is_scraping, reason = detector.detect(
            client_ip,
            time_window_seconds=time_window_seconds,
            rate_threshold=rate_threshold,
            distinct_threshold=distinct_threshold,
        )
        if not is_scraping:
            continue
        # Explainable endpoint: most common normalized path for this actor
        # (tie-break: lexicographically smallest for determinism).
        norm_counts = Counter(normalize_path(p) for p, _, _ in entries)
        top_count = max(norm_counts.values())
        endpoint = sorted(p for p, c in norm_counts.items() if c == top_count)[0]
        methods = Counter(
            str(r.get("method", "")).upper() for _, _, r in entries if r.get("method")
        )
        top_method = methods.most_common(1)[0][0] if methods else ""
        latest_seen = max(e[1] for e in entries)
        # Distinct count within the detector window for metadata:
        # same cutoff logic as the detector (relative to latest ts).
        cutoff = entries[-1][1] - timedelta(seconds=time_window_seconds)
        recent = [(p, ts) for p, ts, _ in entries if ts >= cutoff]
        distinct_recent = len({p for p, _ in recent})
        risk = _score_single(scorer, "scraping", reason)
        findings.append(
            {
                "detection_type": "scraping",
                "endpoint": endpoint,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": latest_seen.isoformat()
                if isinstance(latest_seen, datetime)
                else _utcnow_iso(),
                "metadata": {
                    "client_ip": client_ip,
                    "method": top_method,
                    "request_count": len(recent),
                    "distinct_resources": distinct_recent,
                    "time_window_seconds": time_window_seconds,
                    "rate_threshold": rate_threshold,
                    "distinct_threshold": distinct_threshold,
                    "breakdown": risk.breakdown,
                },
            }
        )
    return findings


def analyze_bola_cases(
    cases: list[dict],
    scorer: RiskScorer | None = None,
) -> list[dict]:
    """Run BOLA detection over explicit authorization cases.

    Each case: ``{"user_id": str, "resource_id": str,
    "authorized_resource_ids": set/list, "endpoint": str (optional),
    "timestamp": str (optional)}``.
    Requires explicit context — never inferred from traffic.
    """
    if scorer is None:
        scorer = RiskScorer()
    findings: list[dict] = []
    detector = BOLADetector()
    for case in cases:
        if not isinstance(case, dict):
            continue
        user_id = case.get("user_id")
        resource_id = case.get("resource_id")
        authorized = case.get("authorized_resource_ids")
        if not user_id or not resource_id or authorized is None:
            continue  # incomplete event data: skip, don't flag
        try:
            auth_set = set(authorized)
        except TypeError:
            continue
        is_bola, reason = detector.detect(str(user_id), str(resource_id), auth_set)
        if not is_bola:
            continue
        risk = _score_single(scorer, "bola", reason)
        findings.append(
            {
                "detection_type": "bola",
                "endpoint": str(case.get("endpoint") or f"/resources/{resource_id}"),
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": str(case.get("timestamp") or _utcnow_iso()),
                "metadata": {
                    "user_id": str(user_id),
                    "resource_id": str(resource_id),
                    "breakdown": risk.breakdown,
                },
            }
        )
    findings.sort(key=lambda f: (f["detection_type"], f["endpoint"]))
    return findings


def analyze_token_replay_cases(
    token_uses: list[dict] | None = None,
    checks: list[dict] | None = None,
    scorer: RiskScorer | None = None,
) -> list[dict]:
    """Run token-replay detection over explicit token events.

    ``token_uses``: prior observations
    ``{"token": str, "user_id": str, "ip_address": str, "timestamp": datetime/str}``.
    ``checks``: current requests to evaluate (same shape + optional
    ``max_ip_changes`` and ``endpoint``).
    Raw tokens are fingerprinted immediately and never included in findings;
    only the 16-char fingerprint is kept in metadata.
    """
    if scorer is None:
        scorer = RiskScorer()
    detector = TokenReplayDetector()
    for use in token_uses or []:
        if not isinstance(use, dict):
            continue
        token = use.get("token")
        user_id = use.get("user_id")
        ip = use.get("ip_address")
        ts = use.get("timestamp")
        if not token or not user_id or not ip or ts is None:
            continue
        detector.record_token_use(str(token), str(user_id), str(ip), _ensure_timestamp(ts))

    findings: list[dict] = []
    for check in checks or []:
        if not isinstance(check, dict):
            continue
        token = check.get("token")
        user_id = check.get("user_id")
        ip = check.get("ip_address")
        ts = check.get("timestamp")
        if not token or not user_id or not ip or ts is None:
            continue
        ts = _ensure_timestamp(ts)
        try:
            max_ips = int(check.get("max_ip_changes", DEFAULT_MAX_IP_CHANGES))
        except (TypeError, ValueError):
            max_ips = DEFAULT_MAX_IP_CHANGES
        is_replay, reason = detector.detect(
            str(token), str(user_id), str(ip), ts, max_ip_changes=max_ips
        )
        # Record this use too so subsequent checks see the history
        # (mirrors real-world sequential analysis; deterministic order).
        detector.record_token_use(str(token), str(user_id), str(ip), ts)
        if not is_replay:
            continue
        risk = _score_single(scorer, "token_replay", reason)
        fingerprint = TokenReplayDetector.fingerprint_token(str(token))
        timestamp = ts.isoformat() if isinstance(ts, datetime) else _utcnow_iso()
        findings.append(
            {
                "detection_type": "token_replay",
                "endpoint": str(check.get("endpoint") or "/auth/token"),
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": timestamp,
                "metadata": {
                    "token_fingerprint": fingerprint,
                    "ip_address": str(ip),
                    "max_ip_changes": max_ips,
                    "breakdown": risk.breakdown,
                },
            }
        )
    findings.sort(key=lambda f: (f["detection_type"], f["endpoint"]))
    return findings


def analyze_captured_traffic(
    records: list[dict],
    *,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
    rate_threshold: int = DEFAULT_RATE_THRESHOLD,
    distinct_threshold: int = DEFAULT_DISTINCT_THRESHOLD,
    bola_cases: list[dict] | None = None,
    token_uses: list[dict] | None = None,
    token_checks: list[dict] | None = None,
) -> list[dict]:
    """Full pipeline: captures -> detectors -> scored, sorted findings.

    - Scraping findings come from ``records`` (capture store).
    - BOLA findings come only from explicit ``bola_cases`` (auth context).
    - Token-replay findings come only from explicit ``token_uses``/``checks``.
    With no explicit context, only scraping is evaluated — never inventing
    users, auth maps, or tokens from traffic.
    """
    if not isinstance(records, list):
        records = []
    scorer = RiskScorer()
    findings = analyze_scraping_from_captures(
        records,
        scorer,
        time_window_seconds=time_window_seconds,
        rate_threshold=rate_threshold,
        distinct_threshold=distinct_threshold,
    )
    if bola_cases:
        findings.extend(analyze_bola_cases(bola_cases, scorer))
    if token_uses or token_checks:
        findings.extend(
            analyze_token_replay_cases(token_uses or [], token_checks or [], scorer)
        )
    findings.sort(key=lambda f: (f["detection_type"], f["endpoint"]))
    return findings
