"""Integration analysis pipeline: captured traffic -> detectors -> findings.

Connects the discovery side (sanitized capture records from ``app.storage``)
with the security side (``app.abuse_detection`` + ``app.risk_scoring``).

Design decisions (see docs/integration-decisions.md):
- Scraping is derived from capture. Its actor is
  ``client_ip`` (the only identity capture stores), resource is the raw
  path without query string (preserves distinct-object counting; normalized
  paths would collapse /users/1../users/100 into one object and miss
  scraping), timestamp is the server-side ``created_at``.
- Capture also feeds two attempt-level detectors (no ownership needed):
  BOLA enumeration (one actor probing many object IDs on one template with
  mostly 401/403/404 responses) and token replay (one keyed credential
  fingerprint from many IPs). Actor = ``actor_fp`` if present, else IP.
- Confirmed BOLA and raw-token replay REQUIRE explicit authorization
  context / token inputs. Captured records contain no user IDs, auth maps, or tokens (by
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
# Enumeration uses its own, longer window (as Akto's ParamEnumerationDetector
# does) so low-and-slow ID probing under the scraping rate limit is caught.
DEFAULT_ENUM_WINDOW_SECONDS = 300
DEFAULT_ENUM_DISTINCT_IDS = 10
DEFAULT_ENUM_DENIED_RATIO = 0.5
DENIED_STATUSES = frozenset({401, 403, 404})
DEFAULT_REPLAY_WINDOW_SECONDS = 3600


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


def _score_escalated(
    scorer: RiskScorer, detector: str, reason: str, magnitude: float, method: str, endpoint: str
):
    """One detector signal plus magnitude/context escalation (capture detectors)."""
    return scorer.escalate(
        _score_single(scorer, detector, reason),
        magnitude=magnitude, method=method, endpoint=endpoint,
    )


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


def _last_breaching_end(
    entries: list[tuple[str, datetime, dict]],
    window_seconds: int,
    rate_threshold: int,
    distinct_threshold: int,
) -> int | None:
    """Index of the last request whose trailing window breaches a threshold.

    Same window rule as ``ScrapingDetector.detect`` (ts >= end - window),
    evaluated at every request with two pointers, O(n).
    """
    last = None
    start = 0
    paths: Counter = Counter()
    for end, (path, ts, _) in enumerate(entries):
        paths[path] += 1
        while entries[start][1] < ts - timedelta(seconds=window_seconds):
            old = entries[start][0]
            paths[old] -= 1
            if not paths[old]:
                del paths[old]
            start += 1
        if end - start + 1 > rate_threshold or len(paths) > distinct_threshold:
            last = end
    return last


def analyze_scraping_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
    rate_threshold: int = DEFAULT_RATE_THRESHOLD,
    distinct_threshold: int = DEFAULT_DISTINCT_THRESHOLD,
    all_windows: bool = False,
) -> list[dict]:
    """Run scraping detection over sanitized capture records.

    Groups by ``client_ip``; feeds each group into ``ScrapingDetector``
    with raw paths as object IDs. Returns finding dicts (unsorted;
    use ``analyze_captured_traffic`` for sorted, scored output).
    Malformed records (missing path/timestamp) are skipped gracefully.

    ``all_windows=False`` (default, GET /api/findings): only each actor's
    latest window counts, so a finding expires once the burst is past.
    ``all_windows=True`` (POST /api/scan): report each actor's most recent
    *breaching* window, so a burst is not lost if no scan ran during it.
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
        if all_windows:
            end = _last_breaching_end(
                entries, time_window_seconds, rate_threshold, distinct_threshold
            )
            if end is None:
                continue
            entries = entries[: end + 1]  # evaluate as if scanned at that moment
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
        # Requests inside the detector window: same cutoff logic as the
        # detector (relative to latest ts), so attribution and metadata
        # describe the traffic that actually triggered the finding.
        cutoff = entries[-1][1] - timedelta(seconds=time_window_seconds)
        recent = [(p, ts, r) for p, ts, r in entries if ts >= cutoff]
        distinct_recent = len({p for p, _, _ in recent})
        # Explainable endpoint: most common normalized path in the window
        # (tie-break: lexicographically smallest for determinism).
        norm_counts = Counter(normalize_path(p) for p, _, _ in recent)
        top_count = max(norm_counts.values())
        endpoint = sorted(p for p, c in norm_counts.items() if c == top_count)[0]
        methods = Counter(
            str(r.get("method", "")).upper() for _, _, r in recent if r.get("method")
        )
        top_method = methods.most_common(1)[0][0] if methods else ""
        latest_seen = max(e[1] for e in entries)
        magnitude = max(len(recent) / max(rate_threshold, 1), distinct_recent / max(distinct_threshold, 1))
        risk = _score_escalated(scorer, "scraping", reason, magnitude, top_method, endpoint)
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


def _actor(rec: dict) -> tuple[str, str]:
    """(actor, actor_type): credential fingerprint if present, else client IP."""
    fp = rec.get("actor_fp")
    if fp:
        return str(fp), "credential"
    return str(rec.get("client_ip") or "unknown"), "ip"


def _id_segments(raw_path: str) -> tuple[str, ...]:
    """Raw values of the segments that normalize_path turns into ``{id}``."""
    raw = [seg for seg in raw_path.split("/") if seg]
    norm = [seg for seg in normalize_path(raw_path).split("/") if seg]
    return tuple(r for r, n in zip(raw, norm) if n == "{id}")


def _timed_records(records: list[dict]) -> list[tuple[datetime, dict]]:
    """Records with a parseable timestamp, oldest first (malformed skipped)."""
    timed = []
    for rec in records or []:
        if isinstance(rec, dict):
            ts = parse_created_at(rec.get("created_at"))
            if ts is not None:
                timed.append((ts, rec))
    timed.sort(key=lambda e: e[0])
    return timed


def _in_window(entries: list, window_seconds: int) -> list:
    """Entries (ts-first tuples, sorted) within window of the latest one."""
    cutoff = entries[-1][0] - timedelta(seconds=window_seconds)
    return [e for e in entries if e[0] >= cutoff]


def analyze_enumeration_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    window_seconds: int = DEFAULT_ENUM_WINDOW_SECONDS,
    distinct_id_threshold: int = DEFAULT_ENUM_DISTINCT_IDS,
    denied_ratio_threshold: float = DEFAULT_ENUM_DENIED_RATIO,
) -> list[dict]:
    """Flag BOLA-style object-ID probing from captured traffic alone.

    Per (actor, method, ID-bearing template), within a rolling window: more
    than ``distinct_id_threshold`` distinct IDs AND at least
    ``denied_ratio_threshold`` of responses 401/403/404. Bulk successful
    reads are left to the scraping detector. A probe is an attempt signal,
    not proof of a successful BOLA (that needs ownership context).
    """
    if scorer is None:
        scorer = RiskScorer()
    groups: dict[tuple, list[tuple[datetime, tuple, int]]] = defaultdict(list)
    actor_types: dict[str, str] = {}
    for ts, rec in _timed_records(records):
        raw_path = raw_path_without_query(rec.get("path"))
        ids = _id_segments(raw_path)
        if not ids:
            continue
        actor, actor_type = _actor(rec)
        actor_types[actor] = actor_type
        key = (actor, str(rec.get("method", "")).upper(), normalize_path(raw_path))
        groups[key].append((ts, ids, rec.get("status_code", 0)))

    findings: list[dict] = []
    for (actor, method, template), entries in sorted(groups.items()):
        recent = _in_window(entries, window_seconds)
        distinct_ids = len({ids for _, ids, _ in recent})
        denied = sum(1 for _, _, status in recent if status in DENIED_STATUSES)
        denied_ratio = round(denied / len(recent), 2)
        if distinct_ids <= distinct_id_threshold or denied_ratio < denied_ratio_threshold:
            continue
        reason = (
            f"Actor {actor} requested {distinct_ids} distinct IDs on {method} "
            f"{template} in {window_seconds}s; {denied}/{len(recent)} were denied "
            f"(401/403/404) - likely object-ID enumeration (BOLA attempt)"
        )
        risk = _score_escalated(
            scorer, "bola", reason, distinct_ids / max(distinct_id_threshold, 1), method, template
        )
        findings.append(
            {
                "detection_type": "bola_enumeration",
                "endpoint": template,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": recent[-1][0].isoformat(),
                "metadata": {
                    "actor": actor,
                    "actor_type": actor_types[actor],
                    "method": method,
                    "request_count": len(recent),
                    "distinct_ids": distinct_ids,
                    "denied_ratio": denied_ratio,
                    "window_seconds": window_seconds,
                    "distinct_id_threshold": distinct_id_threshold,
                    "breakdown": risk.breakdown,
                },
            }
        )
    return findings


def analyze_token_replay_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    max_ips: int = DEFAULT_MAX_IP_CHANGES,
) -> list[dict]:
    """Flag one credential fingerprint used from more than ``max_ips`` IPs.

    Uses only the keyed ``actor_fp`` stored at capture time (raw credentials
    are never available here). Anonymous records are ignored.
    """
    if scorer is None:
        scorer = RiskScorer()
    by_fp: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for ts, rec in _timed_records(records):
        if rec.get("actor_fp"):
            by_fp[str(rec["actor_fp"])].append((ts, rec))

    findings: list[dict] = []
    for fp, entries in sorted(by_fp.items()):
        recent = _in_window(entries, window_seconds)
        ips = sorted({str(r.get("client_ip") or "unknown") for _, r in recent})
        if len(ips) <= max_ips:
            continue
        norm_counts = Counter(
            normalize_path(raw_path_without_query(r.get("path"))) for _, r in recent
        )
        top = max(norm_counts.values())
        endpoint = sorted(p for p, c in norm_counts.items() if c == top)[0]
        reason = (
            f"Credential fingerprint {fp[:8]}... used from {len(ips)} different IPs "
            f"in {window_seconds}s (threshold: {max_ips})"
        )
        risk = _score_escalated(scorer, "token_replay", reason, len(ips) / max(max_ips, 1), "", endpoint)
        findings.append(
            {
                "detection_type": "token_replay",
                "endpoint": endpoint,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": recent[-1][0].isoformat(),
                "metadata": {
                    "token_fingerprint": fp,
                    "source": "capture",
                    "distinct_ips": len(ips),
                    "ips": ips,
                    "request_count": len(recent),
                    "window_seconds": window_seconds,
                    "max_ips": max_ips,
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
    scraping_all_windows: bool = False,
) -> list[dict]:
    """Full pipeline: captures -> detectors -> scored, sorted findings.

    - Scraping, BOLA-enumeration and capture-based token-replay findings
      come from ``records`` (capture store).
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
        all_windows=scraping_all_windows,
    )
    findings.extend(analyze_enumeration_from_captures(records, scorer))
    findings.extend(analyze_token_replay_from_captures(records, scorer))
    if bola_cases:
        findings.extend(analyze_bola_cases(bola_cases, scorer))
    if token_uses or token_checks:
        findings.extend(
            analyze_token_replay_cases(token_uses or [], token_checks or [], scorer)
        )
    findings.sort(key=lambda f: (f["detection_type"], f["endpoint"]))
    return findings


def alert_actor(finding: dict) -> str:
    """Dedup actor for a finding: who did it, from its safe metadata."""
    md = finding.get("metadata") or {}
    for key in ("actor", "token_fingerprint", "client_ip", "user_id"):
        if md.get(key):
            return str(md[key])
    return "unknown"
