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
from datetime import datetime, timedelta
from typing import Any

from app.abuse_detection import BOLADetector, ScrapingDetector, TokenReplayDetector
from app.discovery import id_segments, normalize_path, path_only
from app.risk_scoring import RiskScorer
from app.runtime_monitor import build_runtime_baselines
from app.timeutil import parse_timestamp, to_utc_naive, utcnow

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
# Low-and-slow enumeration: the same distinct-ID and denial thresholds over the hour-long window
# the scraping detector already uses for low-and-slow harvesting (SLOW_WINDOW_SECONDS), so probing
# paced to stay under the 5-minute burst window is still seen. No new threshold is introduced.
ENUM_SLOW_WINDOW_SECONDS = 3600
DEFAULT_REPLAY_WINDOW_SECONDS = 3600
# Tuned in Phase 2 (see docs/PHASE2_REPORT.md for the measured effect):
# the rate rule needs this many distinct paths, so polling a handful of
# endpoints is not scraping.
DEFAULT_MIN_DISTINCT_FOR_RATE = 5
# Low-and-slow harvesting: many requests across many paths over an hour.
SLOW_WINDOW_SECONDS = 3600
SLOW_REQUEST_THRESHOLD = 100
SLOW_MIN_DISTINCT = 20
# Token replay needs rapid hops between IPs: a credential seen from a new IP
# within this many seconds of its previous request. Roaming users that move
# between networks minutes or hours apart are not flagged.
REPLAY_SWITCH_GAP_SECONDS = 60
# Repeated authentication/authorization failures (Phase 5): one actor, many 401/403.
AUTH_FAIL_WINDOW_SECONDS = 300
AUTH_FAIL_MIN_DENIED = 10
AUTH_FAIL_MIN_RATIO = 0.5
AUTH_FAIL_STATUSES = frozenset({401, 403})
# Baseline anomalies (Phase 5). Rate anomalies reuse app.runtime_monitor (same-hour-of-week
# median, >= 3 matching historical buckets). Error/payload rules compare a short recent
# window with the endpoint's own earlier traffic and stay silent without enough history.
ANOMALY_BASELINE_DAYS = 28
ANOMALY_WINDOW_SECONDS = 300
ANOMALY_HISTORY_DAYS = 7
ANOMALY_MIN_HISTORY = 20
ERROR_MIN_REQUESTS = 10
ERROR_MIN_RATIO = 0.5
ERROR_MAX_BASELINE_RATIO = 0.1
PAYLOAD_MIN_BYTES = 1024
PAYLOAD_FACTOR = 4

# Every finding carries ``metadata.rule_id``; this catalog explains each rule (served with
# alert details). Thresholds in the text are the defaults; metadata holds the values used.
RULES = {
    "SCRAPE-BURST": ("scraping", "Burst harvesting",
                     f"One caller sent more than {DEFAULT_RATE_THRESHOLD} requests over at least "
                     f"{DEFAULT_MIN_DISTINCT_FOR_RATE} distinct paths, or more than {DEFAULT_DISTINCT_THRESHOLD} "
                     f"distinct paths, within {DEFAULT_TIME_WINDOW_SECONDS} s. Repeated reads of the same few "
                     "paths (polling, pagination of one path) do not count."),
    "SCRAPE-SLOW": ("scraping", "Low-and-slow harvesting",
                    f"One caller sent more than {SLOW_REQUEST_THRESHOLD} requests over at least "
                    f"{SLOW_MIN_DISTINCT} distinct paths within {SLOW_WINDOW_SECONDS} s."),
    "SCRAPE-ROTATION": ("scraping", "Credential rotation",
                        "One client IP presented many credentials, each making only a few requests, "
                        "across many paths within 60 s."),
    "BOLA-ENUM": ("bola", "Object-ID enumeration (attempt)",
                  f"One caller requested more than {DEFAULT_ENUM_DISTINCT_IDS} distinct object IDs on one "
                  f"route within {DEFAULT_ENUM_WINDOW_SECONDS} s and at least "
                  f"{int(DEFAULT_ENUM_DENIED_RATIO * 100)}% were answered 401/403/404. An attempt signal, "
                  "not proof that data was disclosed."),
    "BOLA-ENUM-SLOW": ("bola", "Low-and-slow object-ID enumeration (attempt)",
                       f"One caller requested more than {DEFAULT_ENUM_DISTINCT_IDS} distinct object IDs on one "
                       f"route within {ENUM_SLOW_WINDOW_SECONDS} s (paced below the {DEFAULT_ENUM_WINDOW_SECONDS} s "
                       f"burst window) and at least {int(DEFAULT_ENUM_DENIED_RATIO * 100)}% were answered "
                       "401/403/404. An attempt signal, not proof that data was disclosed."),
    "BOLA-CONFIRMED": ("bola", "Confirmed cross-user object access",
                       "A caller mapped to one user received a 2xx response with content for an object "
                       "that the ownership context assigns to a different user."),
    "BOLA-BLOCKED": ("bola", "Blocked cross-user attempt",
                     "A caller mapped to one user requested another user's object and was refused "
                     "(401/403/404). The attempt is recorded; it is not a confirmed vulnerability."),
    "BOLA-INCONCLUSIVE": ("bola", "Inconclusive cross-user attempt",
                          "A caller requested another user's object and the response (204, 3xx, 5xx or "
                          "another 4xx) does not show whether the object was disclosed."),
    "BOLA-CASE": ("bola", "Explicit authorization case",
                  "Caller-supplied authorization context shows access to a resource outside the "
                  "user's authorized set."),
    "REPLAY-CONCURRENT": ("token_misuse", "Concurrent credential use from several IPs",
                          f"One credential fingerprint was used from more than {DEFAULT_MAX_IP_CHANGES} IPs "
                          f"within {DEFAULT_REPLAY_WINDOW_SECONDS} s, switching IP within "
                          f"{REPLAY_SWITCH_GAP_SECONDS} s of its previous request. A user roaming between "
                          "networks minutes apart, or retrying from one IP, is not flagged."),
    "REPLAY-CASE": ("token_misuse", "Explicit token-use case",
                    "Caller-supplied token-use history shows the token used by another user or from "
                    "too many IPs."),
    "AUTH-FAILURES": ("unauthorized_access", "Repeated authentication/authorization failures",
                      f"One caller received at least {AUTH_FAIL_MIN_DENIED} 401/403 responses within "
                      f"{AUTH_FAIL_WINDOW_SECONDS} s, at least {int(AUTH_FAIL_MIN_RATIO * 100)}% of its "
                      "requests in that window. Denials already explained by an object-ID enumeration "
                      "finding are not counted twice."),
    "ANOMALY-RATE": ("anomaly", "Endpoint request-rate anomaly",
                     "The current hour's request count exceeds max(3 x median, median + 3 x 1.4826 x MAD, 5) "
                     "of the same weekday/hour in earlier weeks; needs at least 3 matching historical "
                     "hours, so a recurring peak is not an anomaly."),
    "ANOMALY-CALLER-RATE": ("anomaly", "Caller request-rate anomaly",
                            "One caller's current-hour request count on an endpoint exceeds its own "
                            "same-weekday/hour baseline (same rule and history requirement as ANOMALY-RATE)."),
    "ANOMALY-ERRORS": ("anomaly", "Server-error spike",
                       f"At least {ERROR_MIN_REQUESTS} requests and {int(ERROR_MIN_RATIO * 100)}% 5xx on one "
                       f"endpoint within {ANOMALY_WINDOW_SECONDS} s, while the previous {ANOMALY_HISTORY_DAYS} "
                       f"days (>= {ANOMALY_MIN_HISTORY} requests) had under {int(ERROR_MAX_BASELINE_RATIO * 100)}% 5xx."),
    "ANOMALY-PAYLOAD": ("anomaly", "Request-payload size anomaly",
                        f"A caller sent request bodies larger than max({PAYLOAD_MIN_BYTES} bytes, "
                        f"{PAYLOAD_FACTOR} x the endpoint's 95th-percentile size over the previous "
                        f"{ANOMALY_HISTORY_DAYS} days, >= {ANOMALY_MIN_HISTORY} requests) within {ANOMALY_WINDOW_SECONDS} s."),
}
# Detection type -> investigation category (incident grouping, endpoint risk factors).
CATEGORIES = {
    "scraping": "scraping", "bola": "bola", "bola_enumeration": "bola", "bola_blocked": "bola",
    "bola_inconclusive": "bola",
    "token_replay": "token_misuse", "access_denied": "unauthorized_access",
    "rate_anomaly": "anomaly", "error_spike": "anomaly", "payload_anomaly": "anomaly",
}


def _evidence(rows: list[tuple[datetime, dict]]) -> dict:
    """Common, safe evidence for the requests behind a finding (oldest first)."""
    statuses = Counter(str(r.get("status_code", "")) for _, r in rows)
    endpoints = Counter(
        f"{str(r.get('method', '')).upper()} {normalize_path(raw_path_without_query(r.get('path')))}"
        for _, r in rows
    )
    return {
        "first_seen": rows[0][0].isoformat(),
        "last_seen": rows[-1][0].isoformat(),
        "status_counts": dict(sorted(statuses.items())),
        "endpoints": [e for e, _ in sorted(endpoints.items(), key=lambda kv: (-kv[1], kv[0]))[:10]],
    }


def _longest_sequential_run(paths) -> int:
    """Longest run of consecutive numeric object IDs (systematic walking evidence)."""
    nums = sorted({int(s) for p in paths for s in id_segments(p) if s.isdigit() and len(s) < 12})
    best = run = 1 if nums else 0
    for a, b in zip(nums, nums[1:]):
        run = run + 1 if b == a + 1 else 1
        best = max(best, run)
    return best


def _ensure_timestamp(ts: Any) -> datetime:
    """Normalize a value to naive UTC; fall back to now (UTC) if unusable."""
    return parse_timestamp(ts) or utcnow()


def parse_created_at(value: Any) -> datetime | None:
    """Parse a ``created_at`` value from storage into naive UTC.

    Accepts datetimes (zone-aware ones are converted to UTC), SQLite
    ``YYYY-MM-DD HH:MM:SS`` strings and ISO-8601 strings. Returns None for
    missing or malformed values; callers skip such records.
    """
    return parse_timestamp(value)


def raw_path_without_query(path: Any) -> str:
    """Return the path component without query string (safe, no values)."""
    if not isinstance(path, str) or not path:
        return "/"
    return path_only(path) or "/"


def _utcnow_iso() -> str:
    return utcnow().isoformat()


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
    elif detector in scorer.SIGNAL_WEIGHTS:
        return scorer.score_signal(detector, reason)
    return scorer.calculate_score(**kwargs)


def _last_breaching_end(
    entries: list[tuple[str, datetime, dict]],
    window_seconds: int,
    rate_threshold: int,
    distinct_threshold: int,
    min_distinct_for_rate: int = 1,
) -> int | None:
    """Index of the last request whose trailing window breaches a threshold.

    Same window rule as ``ScrapingDetector.detect`` (ts >= end - window,
    rate rule gated by ``min_distinct_for_rate``), evaluated at every request
    with two pointers, O(n).
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
        if (
            end - start + 1 > rate_threshold and len(paths) >= min_distinct_for_rate
        ) or len(paths) > distinct_threshold:
            last = end
    return last


def analyze_scraping_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS,
    rate_threshold: int = DEFAULT_RATE_THRESHOLD,
    distinct_threshold: int = DEFAULT_DISTINCT_THRESHOLD,
    min_distinct_for_rate: int = DEFAULT_MIN_DISTINCT_FOR_RATE,
    detect_low_and_slow: bool = True,
    all_windows: bool = False,
    now: datetime | None = None,
) -> list[dict]:
    """Run scraping detection over sanitized capture records.

    Groups by actor (``_actor``: credential fingerprint, else client IP) and
    feeds each group into ``ScrapingDetector`` with raw paths as object IDs. Returns finding dicts (unsorted;
    use ``analyze_captured_traffic`` for sorted, scored output).
    Malformed records (missing path/timestamp) are skipped gracefully.

    Two patterns per actor, first match wins: a ``burst`` (rate or distinct
    paths inside ``time_window_seconds``; the rate rule needs
    ``min_distinct_for_rate`` distinct paths) and ``low_and_slow`` (many
    requests over many paths within an hour).

    ``all_windows=False`` (default, GET /api/findings): only the live window
    counts, so a finding expires once the burst is past. The window ends at
    ``now`` when given (idle actors expire), else at the actor's latest request.
    ``all_windows=True`` (POST /api/scan): report each actor's most recent
    *breaching* window, so a burst is not lost if no scan ran during it.
    """
    if scorer is None:
        scorer = RiskScorer()
    if not records:
        return []
    grouped: dict[str, list[tuple[str, datetime, dict]]] = defaultdict(list)
    actor_types: dict[str, str] = {}
    for rec in records:
        if not isinstance(rec, dict):
            continue
        actor, actor_type = _actor(rec)
        raw_path = raw_path_without_query(rec.get("path", "/"))
        ts = parse_created_at(rec.get("created_at"))
        if ts is None:
            continue
        actor_types[actor] = actor_type
        grouped[actor].append((raw_path, ts, rec))

    # (pattern, window, request threshold, distinct threshold, min distinct for rate)
    profiles = [
        ("burst", time_window_seconds, rate_threshold, distinct_threshold, min_distinct_for_rate)
    ]
    if detect_low_and_slow:
        profiles.append(
            ("low_and_slow", SLOW_WINDOW_SECONDS, SLOW_REQUEST_THRESHOLD, 10**9, SLOW_MIN_DISTINCT)
        )

    findings: list[dict] = []
    for actor in sorted(grouped):
        everything = sorted(grouped[actor], key=lambda e: e[1])
        for pattern, window, rate, distinct, min_distinct in profiles:
            entries = everything
            if now is not None and not all_windows:
                cutoff_now = now - timedelta(seconds=window)
                entries = [e for e in entries if e[1] >= cutoff_now]
                if not entries:
                    continue
            if all_windows:
                end = _last_breaching_end(entries, window, rate, distinct, min_distinct)
                if end is None:
                    continue
                entries = entries[: end + 1]  # evaluate as if scanned at that moment
            detector = ScrapingDetector()
            for raw_path, ts, _ in entries:
                detector.record_request(actor, raw_path, ts)
            is_scraping, reason = detector.detect(
                actor,
                time_window_seconds=window,
                rate_threshold=rate,
                distinct_threshold=distinct,
                min_distinct_for_rate=min_distinct,
            )
            if not is_scraping:
                continue
            # Requests inside the detector window: same cutoff logic as the
            # detector (relative to latest ts), so attribution and metadata
            # describe the traffic that actually triggered the finding.
            cutoff = entries[-1][1] - timedelta(seconds=window)
            recent = [(p, ts, r) for p, ts, r in entries if ts >= cutoff]
            distinct_recent = len({p for p, _, _ in recent})
            if pattern == "low_and_slow":
                reason = f"Low-and-slow harvesting: {reason}; {distinct_recent} distinct paths"
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
            distinct_ref = min_distinct if distinct >= 10**9 else distinct
            magnitude = max(len(recent) / max(rate, 1), distinct_recent / max(distinct_ref, 1))
            risk = _score_escalated(scorer, "scraping", reason, magnitude, top_method, endpoint)
            findings.append(
                {
                    "detection_type": "scraping",
                    "endpoint": endpoint,
                    "risk_score": risk.score,
                    "reason": reason,
                    "timestamp": latest_seen.isoformat(),
                    "metadata": {
                        **_evidence([(ts, rec) for _, ts, rec in recent]),
                        "rule_id": "SCRAPE-BURST" if pattern == "burst" else "SCRAPE-SLOW",
                        "sequential_id_run": _longest_sequential_run(p for p, _, _ in recent),
                        "actor": actor,
                        "actor_type": actor_types[actor],
                        "client_ip": str(entries[-1][2].get("client_ip") or "unknown"),
                        "pattern": pattern,
                        "method": top_method,
                        "request_count": len(recent),
                        "distinct_resources": distinct_recent,
                        "time_window_seconds": window,
                        "rate_threshold": rate,
                        "distinct_threshold": distinct if distinct < 10**9 else None,
                        "breakdown": risk.breakdown,
                        "reasons": risk.reasons,
                    },
                }
            )
            break  # one finding per actor: the first (burst) pattern wins
    return findings


# Credential rotation: one IP presenting many distinct credentials, each making
# only a few requests, so no single credential trips the per-credential rule.
# Reported against the IP, separately from per-credential scraping. Shared NAT
# offices can look the same; the thresholds keep small offices quiet.
ROTATION_WINDOW_SECONDS = 60
ROTATION_MIN_CREDENTIALS = 10
ROTATION_MIN_REQUESTS = 40
ROTATION_MAX_PER_CREDENTIAL = 10
ROTATION_MIN_DISTINCT_PATHS = 20


def _rotation_breaches(counts_fp: Counter, counts_path: Counter, n: int) -> bool:
    return (
        n >= ROTATION_MIN_REQUESTS
        and len(counts_fp) >= ROTATION_MIN_CREDENTIALS
        and max(counts_fp.values()) <= ROTATION_MAX_PER_CREDENTIAL
        and len(counts_path) >= ROTATION_MIN_DISTINCT_PATHS
    )


def analyze_credential_rotation_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    now: datetime | None = None,
    all_windows: bool = False,
) -> list[dict]:
    """Flag one client IP that presents many credential fingerprints at high volume.

    Only requests that carry a credential fingerprint are considered; anonymous
    traffic is left to per-IP scraping. Same window semantics as scraping:
    ``now`` given and not ``all_windows`` checks the live window ending at
    ``now``; otherwise the most recent breaching window per IP is reported.
    """
    if scorer is None:
        scorer = RiskScorer()
    by_ip: dict[str, list[tuple[datetime, str, str, dict]]] = defaultdict(list)
    for rec in records or []:
        if not isinstance(rec, dict) or not rec.get("actor_fp"):
            continue
        ts = parse_created_at(rec.get("created_at"))
        if ts is None:
            continue
        ip = str(rec.get("client_ip") or "unknown")
        by_ip[ip].append((ts, str(rec["actor_fp"]), raw_path_without_query(rec.get("path", "/")), rec))

    window = timedelta(seconds=ROTATION_WINDOW_SECONDS)
    findings: list[dict] = []
    for ip in sorted(by_ip):
        entries = sorted(by_ip[ip], key=lambda e: e[0])
        if now is not None and not all_windows:
            entries = [e for e in entries if e[0] >= now - window]
            if not _rotation_breaches(
                Counter(e[1] for e in entries), Counter(e[2] for e in entries), len(entries)
            ):
                continue
            span = entries
        else:
            span = None
            counts_fp: Counter = Counter()
            counts_path: Counter = Counter()
            start = 0
            for end, (ts, fp, path, _) in enumerate(entries):
                counts_fp[fp] += 1
                counts_path[path] += 1
                while entries[start][0] < ts - window:
                    _, old_fp, old_path, _ = entries[start]
                    start += 1
                    for counts, key in ((counts_fp, old_fp), (counts_path, old_path)):
                        counts[key] -= 1
                        if counts[key] == 0:
                            del counts[key]
                if _rotation_breaches(counts_fp, counts_path, end - start + 1):
                    span = entries[start : end + 1]
            if span is None:
                continue
        fps = Counter(e[1] for e in span)
        paths = {e[2] for e in span}
        n = len(span)
        norm_counts = Counter(normalize_path(e[2]) for e in span)
        top_count = max(norm_counts.values())
        endpoint = sorted(p for p, c in norm_counts.items() if c == top_count)[0]
        methods = Counter(str(e[3].get("method", "")).upper() for e in span if e[3].get("method"))
        top_method = methods.most_common(1)[0][0] if methods else ""
        reason = (
            f"Credential rotation: {n} requests from {ip} across {len(fps)} credential "
            f"fingerprints in {ROTATION_WINDOW_SECONDS}s (at most {max(fps.values())} per "
            f"credential, {len(paths)} distinct paths); not attributed to a single user"
        )
        magnitude = max(n / ROTATION_MIN_REQUESTS, len(fps) / ROTATION_MIN_CREDENTIALS)
        risk = _score_escalated(scorer, "scraping", reason, magnitude, top_method, endpoint)
        findings.append(
            {
                "detection_type": "scraping",
                "endpoint": endpoint,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": span[-1][0].isoformat(),
                "metadata": {
                    **_evidence([(e[0], e[3]) for e in span]),
                    "rule_id": "SCRAPE-ROTATION",
                    "actor": ip,
                    "actor_type": "ip",
                    "client_ip": ip,
                    "pattern": "credential_rotation",
                    "method": top_method,
                    "request_count": n,
                    "credential_count": len(fps),
                    "max_requests_per_credential": max(fps.values()),
                    "distinct_resources": len(paths),
                    "time_window_seconds": ROTATION_WINDOW_SECONDS,
                    "breakdown": risk.breakdown,
                    "reasons": risk.reasons,
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


def _in_window(entries: list, window_seconds: int, now: datetime | None = None) -> list:
    """Entries (ts-first tuples, sorted) inside the window ending at ``now``
    (default: the latest entry). Boundary is inclusive: ts >= end - window."""
    end = now if now is not None else entries[-1][0]
    cutoff = end - timedelta(seconds=window_seconds)
    return [e for e in entries if e[0] >= cutoff]


def analyze_enumeration_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    window_seconds: int = DEFAULT_ENUM_WINDOW_SECONDS,
    distinct_id_threshold: int = DEFAULT_ENUM_DISTINCT_IDS,
    denied_ratio_threshold: float = DEFAULT_ENUM_DENIED_RATIO,
    detect_low_and_slow: bool = True,
    now: datetime | None = None,
) -> list[dict]:
    """Flag BOLA-style object-ID probing from captured traffic alone.

    Two windows, first match wins per (actor, method, template): the ``window_seconds`` burst
    (BOLA-ENUM) and, when ``detect_low_and_slow``, ENUM_SLOW_WINDOW_SECONDS (BOLA-ENUM-SLOW)
    with the same thresholds, for probing paced below the burst window.

    Per (actor, method, ID-bearing template), within a rolling window: more
    than ``distinct_id_threshold`` distinct IDs AND at least
    ``denied_ratio_threshold`` of responses 401/403/404. Bulk successful
    reads are left to the scraping detector. A probe is an attempt signal,
    not proof of a successful BOLA (that needs ownership context, see
    ``analyze_unauthorized_access_from_captures``).
    """
    if scorer is None:
        scorer = RiskScorer()
    groups: dict[tuple, list[tuple[datetime, tuple, int]]] = defaultdict(list)
    actor_types: dict[str, str] = {}
    for ts, rec in _timed_records(records):
        raw_path = raw_path_without_query(rec.get("path"))
        ids = id_segments(raw_path)
        if not ids:
            continue
        actor, actor_type = _actor(rec)
        actor_types[actor] = actor_type
        key = (actor, str(rec.get("method", "")).upper(), normalize_path(raw_path))
        groups[key].append((ts, ids, rec.get("status_code", 0), rec))

    profiles = [("burst", window_seconds, "BOLA-ENUM")]
    if detect_low_and_slow and ENUM_SLOW_WINDOW_SECONDS > window_seconds:
        profiles.append(("low_and_slow", ENUM_SLOW_WINDOW_SECONDS, "BOLA-ENUM-SLOW"))
    findings: list[dict] = []
    for (actor, method, template), entries in sorted(groups.items()):
        for pattern, window, rule_id in profiles:
            recent = _in_window(entries, window, now)
            if not recent:
                continue
            distinct_ids = len({ids for _, ids, _, _ in recent})
            denied = sum(1 for _, _, status, _ in recent if status in DENIED_STATUSES)
            denied_ratio = round(denied / len(recent), 2)
            if distinct_ids > distinct_id_threshold and denied_ratio >= denied_ratio_threshold:
                break
        else:
            continue
        reason = (
            f"{'Low-and-slow: ' if pattern == 'low_and_slow' else ''}Actor {actor} requested "
            f"{distinct_ids} distinct IDs on {method} {template} in {window}s; {denied}/{len(recent)} "
            f"were denied (401/403/404) - likely object-ID enumeration (BOLA attempt)"
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
                    **_evidence([(ts, rec) for ts, _, _, rec in recent]),
                    "rule_id": rule_id,
                    "pattern": pattern,
                    "outcome": "attempt",
                    "sample_object_ids": sorted({"/".join(ids) for _, ids, _, _ in recent})[:10],
                    "sequential_id_run": _longest_sequential_run(
                        raw_path_without_query(rec.get("path")) for _, _, _, rec in recent),
                    "actor": actor,
                    "actor_type": actor_types[actor],
                    "client_ip": str(recent[-1][3].get("client_ip") or "unknown"),
                    "method": method,
                    "request_count": len(recent),
                    "distinct_ids": distinct_ids,
                    "denied_ratio": denied_ratio,
                    "window_seconds": window,
                    "distinct_id_threshold": distinct_id_threshold,
                    "breakdown": risk.breakdown,
                    "reasons": risk.reasons,
                },
            }
        )
    return findings


def _status(rec: dict) -> int:
    try:
        return int(rec.get("status_code") or 0)
    except (TypeError, ValueError):
        return 0


def _bola_outcome(status: int) -> str:
    """confirmed: 2xx with content; blocked: 401/403/404; anything else is inconclusive."""
    if 200 <= status < 300 and status != 204:
        return "confirmed"
    if status in DENIED_STATUSES:
        return "blocked"
    return "inconclusive"


BOLA_OUTCOMES = {  # outcome -> (detection_type, rule_id, scoring signal)
    "confirmed": ("bola", "BOLA-CONFIRMED", "bola"),
    "blocked": ("bola_blocked", "BOLA-BLOCKED", "bola_attempt"),
    "inconclusive": ("bola_inconclusive", "BOLA-INCONCLUSIVE", "bola_attempt"),
}


def analyze_unauthorized_access_from_captures(
    records: list[dict],
    ownership: dict | None,
    scorer: RiskScorer | None = None,
    *,
    now: datetime | None = None,
    window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
) -> list[dict]:
    """Cross-user object access, classified by what the response proves.

    Needs operator-supplied ownership context (never inferred from traffic)::

        {"resources": {"/shop/orders/{id}": {"1": "alice", "2": "bob"}},
         "actors": {"<actor_fp or client_ip>": "alice"}}

    For a request from an actor mapped to user U for an object owned by V != U:
    a 2xx response with content is a confirmed BOLA (``bola``); 401/403/404 is a
    blocked attempt (``bola_blocked``, never reported as a vulnerability); any
    other status (204, 3xx, 5xx, other 4xx) is ``bola_inconclusive``. Requests from
    unmapped actors or for unmapped objects are ignored (no context => no claim).
    Results are only as accurate as the supplied context.
    """
    if not ownership:
        return []
    resources = ownership.get("resources") or {}
    users = ownership.get("actors") or {}
    if scorer is None:
        scorer = RiskScorer()
    hits: dict[tuple, list[tuple[datetime, str, str, dict]]] = defaultdict(list)
    actor_types: dict[str, str] = {}
    for ts, rec in _timed_records(records):
        raw_path = raw_path_without_query(rec.get("path"))
        template = normalize_path(raw_path)
        owners = resources.get(template)
        ids = id_segments(raw_path)
        if not owners or not ids:
            continue
        actor, actor_type = _actor(rec)
        user = users.get(actor)
        obj = "/".join(ids)
        owner = owners.get(obj)
        if not user or not owner or owner == user:
            continue
        actor_types[actor] = actor_type
        outcome = _bola_outcome(_status(rec))
        hits[(actor, str(rec.get("method", "")).upper(), template, outcome)].append((ts, obj, owner, rec))

    findings: list[dict] = []
    for (actor, method, template, outcome), entries in sorted(hits.items()):
        recent = _in_window(entries, window_seconds, now)
        if not recent:
            continue
        objects = sorted({obj for _, obj, _, _ in recent})
        user = users[actor]
        detection_type, rule_id, signal = BOLA_OUTCOMES[outcome]
        if outcome == "confirmed":
            reason = (
                f"User {user} successfully read {len(objects)} object(s) owned by other users "
                f"on {method} {template} - confirmed BOLA (broken object-level authorization)"
            )
            magnitude = len(objects)
        else:
            reason = (
                f"User {user} requested {len(objects)} object(s) owned by other users on "
                f"{method} {template}; " + (
                    "every response was a refusal (401/403/404) - blocked attempt, not a confirmed vulnerability"
                    if outcome == "blocked" else
                    "the responses do not show whether data was disclosed - inconclusive"
                )
            )
            magnitude = 1.0
        risk = _score_escalated(scorer, signal, reason, magnitude, method, template)
        findings.append(
            {
                "detection_type": detection_type,
                "endpoint": template,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": recent[-1][0].isoformat(),
                "metadata": {
                    **_evidence([(ts, rec) for ts, _, _, rec in recent]),
                    "rule_id": rule_id,
                    "outcome": outcome,
                    "actor": actor,
                    "actor_type": actor_types[actor],
                    "client_ip": str(recent[-1][3].get("client_ip") or "unknown"),
                    "user_id": user,
                    "method": method,
                    "object_ids": objects[:20],
                    "object_owners": sorted({owner for _, _, owner, _ in recent}),
                    "unauthorized_objects": len(objects),
                    "request_count": len(recent),
                    "source": "ownership_context",
                    "breakdown": risk.breakdown,
                    "reasons": risk.reasons,
                },
            }
        )
    return findings


def analyze_access_denied_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    now: datetime | None = None,
    exclude: frozenset | set = frozenset(),
    window_seconds: int = AUTH_FAIL_WINDOW_SECONDS,
    min_denied: int = AUTH_FAIL_MIN_DENIED,
    min_ratio: float = AUTH_FAIL_MIN_RATIO,
) -> list[dict]:
    """Repeated 401/403 responses for one actor (AUTH-FAILURES).

    ``exclude`` holds (actor, method, template) triples already explained by an
    object-ID enumeration finding, so the same denials are not alerted twice.
    The window ends at ``now`` when given, else at the actor's latest request.
    """
    if scorer is None:
        scorer = RiskScorer()
    by_actor: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    actor_types: dict[str, str] = {}
    for ts, rec in _timed_records(records):
        actor, actor_type = _actor(rec)
        template = normalize_path(raw_path_without_query(rec.get("path")))
        if (actor, str(rec.get("method", "")).upper(), template) in exclude:
            continue
        actor_types[actor] = actor_type
        by_actor[actor].append((ts, rec))

    findings: list[dict] = []
    for actor in sorted(by_actor):
        recent = _in_window(by_actor[actor], window_seconds, now)
        denied = [(ts, r) for ts, r in recent if _status(r) in AUTH_FAIL_STATUSES]
        if len(denied) < min_denied or len(denied) / len(recent) < min_ratio:
            continue
        targets = Counter(
            (str(r.get("method", "")).upper(), normalize_path(raw_path_without_query(r.get("path"))))
            for _, r in denied
        )
        (method, template), _ = sorted(targets.items(), key=lambda kv: (-kv[1], kv[0]))[0]
        ratio = round(len(denied) / len(recent), 2)
        reason = (
            f"Actor {actor} received {len(denied)} denials (401/403) out of {len(recent)} requests "
            f"in {window_seconds}s across {len(targets)} endpoint(s) - repeated unauthorized access attempts"
        )
        risk = _score_escalated(scorer, "access_denied", reason, len(denied) / max(min_denied, 1), method, template)
        findings.append(
            {
                "detection_type": "access_denied",
                "endpoint": template,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": recent[-1][0].isoformat(),
                "metadata": {
                    **_evidence(denied),
                    "rule_id": "AUTH-FAILURES",
                    "actor": actor,
                    "actor_type": actor_types[actor],
                    "client_ip": str(denied[-1][1].get("client_ip") or "unknown"),
                    "method": method,
                    "request_count": len(recent),
                    "denied_count": len(denied),
                    "denied_ratio": ratio,
                    "without_credentials": sum(1 for _, r in denied if r.get("auth_type") == "none"),
                    "window_seconds": window_seconds,
                    "min_denied": min_denied,
                    "min_ratio": min_ratio,
                    "breakdown": risk.breakdown,
                    "reasons": risk.reasons,
                },
            }
        )
    return findings


ALL_CALLERS = "all-callers"  # actor of endpoint-wide anomalies (no single caller)


def _anomaly(scorer, detection_type, rule_id, method, template, actor, reason, magnitude, ts, extra):
    risk = _score_escalated(scorer, "anomaly", reason, magnitude, method, template)
    return {
        "detection_type": detection_type,
        "endpoint": template,
        "risk_score": risk.score,
        "reason": reason,
        "timestamp": ts.isoformat(),
        "metadata": {**extra, "rule_id": rule_id, "actor": actor, "method": method,
                     "breakdown": risk.breakdown, "reasons": risk.reasons},
    }


def analyze_anomalies_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    now: datetime | None = None,
) -> list[dict]:
    """Baseline anomalies: request rate (endpoint and caller), 5xx spikes, payload size.

    Anchored at ``now`` (else the latest record). Every rule needs history and stays
    silent without it, so a first-ever burst or a recurring weekly peak is not reported.
    """
    if scorer is None:
        scorer = RiskScorer()
    timed = _timed_records(records)
    if not timed:
        return []
    anchor = now if now is not None else timed[-1][0]
    findings: list[dict] = []

    base = build_runtime_baselines(records, now=anchor, days=ANOMALY_BASELINE_DAYS)
    for kind, rows in (("endpoint", base["endpoints"]), ("caller", base["callers"])):
        for row in rows:
            if not row["rate_anomaly"]:
                continue
            method, template = row["endpoint"].split(" ", 1)
            actor = ALL_CALLERS if kind == "endpoint" else row["caller"].split(":", 1)[1]
            reason = (
                f"{'Endpoint' if kind == 'endpoint' else 'Caller ' + actor} made "
                f"{row['current_hour_requests']} requests to {method} {template} this hour; the same "
                f"weekday/hour median is {row['baseline_median_requests']} over {row['baseline_samples']} "
                f"earlier weeks (threshold {row['rate_threshold']})"
            )
            findings.append(_anomaly(
                scorer, "rate_anomaly", "ANOMALY-RATE" if kind == "endpoint" else "ANOMALY-CALLER-RATE",
                method, template, actor, reason, row["current_hour_requests"] / max(row["rate_threshold"], 1),
                anchor, {"current_hour_requests": row["current_hour_requests"],
                         "baseline_median_requests": row["baseline_median_requests"],
                         "baseline_samples": row["baseline_samples"],
                         "rate_threshold": row["rate_threshold"],
                         "baseline_days": ANOMALY_BASELINE_DAYS}))

    window_start = anchor - timedelta(seconds=ANOMALY_WINDOW_SECONDS)
    history_start = anchor - timedelta(days=ANOMALY_HISTORY_DAYS)
    groups: dict[tuple[str, str], list[tuple[datetime, dict]]] = defaultdict(list)
    for ts, rec in timed:
        if history_start <= ts <= anchor:
            template = normalize_path(raw_path_without_query(rec.get("path")))
            groups[(str(rec.get("method", "")).upper(), template)].append((ts, rec))
    for (method, template), rows in sorted(groups.items()):
        window = [e for e in rows if e[0] >= window_start]
        history = [e for e in rows if e[0] < window_start]
        if not window or len(history) < ANOMALY_MIN_HISTORY:
            continue
        errors = [e for e in window if _status(e[1]) >= 500]
        base_ratio = round(sum(1 for e in history if _status(e[1]) >= 500) / len(history), 4)
        ratio = round(len(errors) / len(window), 2)
        if len(window) >= ERROR_MIN_REQUESTS and ratio >= ERROR_MIN_RATIO and base_ratio < ERROR_MAX_BASELINE_RATIO:
            reason = (
                f"{len(errors)} of {len(window)} requests to {method} {template} in the last "
                f"{ANOMALY_WINDOW_SECONDS}s returned 5xx ({ratio:.0%}); the previous {ANOMALY_HISTORY_DAYS} "
                f"days had {base_ratio:.1%} over {len(history)} requests"
            )
            callers = Counter(_actor(r)[0] for _, r in errors)
            findings.append(_anomaly(
                scorer, "error_spike", "ANOMALY-ERRORS", method, template, ALL_CALLERS, reason,
                ratio / ERROR_MIN_RATIO, errors[-1][0],
                {**_evidence(window), "window_requests": len(window), "server_errors": len(errors),
                 "error_ratio": ratio, "baseline_requests": len(history), "baseline_error_ratio": base_ratio,
                 "top_callers": [c for c, _ in callers.most_common(5)],
                 "window_seconds": ANOMALY_WINDOW_SECONDS}))
        sizes = sorted(int(r.get("payload_bytes") or 0) for _, r in history)
        p95 = sizes[int(0.95 * (len(sizes) - 1))]
        limit = max(PAYLOAD_MIN_BYTES, PAYLOAD_FACTOR * p95)
        oversized: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
        for ts, rec in window:
            if int(rec.get("payload_bytes") or 0) > limit:
                oversized[_actor(rec)[0]].append((ts, rec))
        for actor, hits in sorted(oversized.items()):
            biggest = max(int(r.get("payload_bytes") or 0) for _, r in hits)
            reason = (
                f"{actor} sent {len(hits)} request(s) to {method} {template} with bodies up to {biggest} "
                f"bytes; the limit is {limit} bytes ({PAYLOAD_FACTOR}x the 95th percentile {p95} over "
                f"{len(history)} earlier requests, minimum {PAYLOAD_MIN_BYTES})"
            )
            findings.append(_anomaly(
                scorer, "payload_anomaly", "ANOMALY-PAYLOAD", method, template, actor, reason,
                biggest / limit, hits[-1][0],
                {**_evidence(hits), "actor_type": _actor(hits[-1][1])[1], "oversized_requests": len(hits),
                 "max_payload_bytes": biggest, "payload_limit_bytes": limit, "baseline_p95_bytes": p95,
                 "baseline_requests": len(history), "window_seconds": ANOMALY_WINDOW_SECONDS}))
    return findings


def analyze_token_replay_from_captures(
    records: list[dict],
    scorer: RiskScorer | None = None,
    *,
    window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    max_ips: int = DEFAULT_MAX_IP_CHANGES,
    rapid_switch_gap_seconds: int | None = REPLAY_SWITCH_GAP_SECONDS,
    now: datetime | None = None,
) -> list[dict]:
    """Flag one credential fingerprint hopping between more than ``max_ips`` IPs.

    Uses only the keyed ``actor_fp`` stored at capture time (raw credentials
    are never available here). Anonymous records are ignored. Identity
    evidence beyond "many IPs in an hour": the credential must switch IP
    within ``rapid_switch_gap_seconds`` of its previous request, i.e. be in
    use from several places at nearly the same time. A user roaming across
    networks minutes apart is not flagged; ``rapid_switch_gap_seconds=None``
    restores the Phase 1 rule (any >max_ips distinct IPs in the window).
    """
    if scorer is None:
        scorer = RiskScorer()
    by_fp: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)
    for ts, rec in _timed_records(records):
        if rec.get("actor_fp"):
            by_fp[str(rec["actor_fp"])].append((ts, rec))

    findings: list[dict] = []
    for fp, entries in sorted(by_fp.items()):
        recent = _in_window(entries, window_seconds, now)
        if not recent:
            continue
        ips = sorted({str(r.get("client_ip") or "unknown") for _, r in recent})
        if len(ips) <= max_ips:
            continue
        hop_ips: set[str] = set()
        hops = 0
        timeline: list[dict] = []  # the IP switches that fired the rule (first 10)
        prev: tuple[datetime, str] | None = None
        for ts, r in recent:
            ip = str(r.get("client_ip") or "unknown")
            if prev and ip != prev[1] and (
                rapid_switch_gap_seconds is None
                or (ts - prev[0]).total_seconds() <= rapid_switch_gap_seconds
            ):
                hop_ips.update((ip, prev[1]))
                hops += 1
                if len(timeline) < 10:
                    timeline.append({"at": ts.isoformat(), "from_ip": prev[1], "to_ip": ip,
                                     "gap_seconds": round((ts - prev[0]).total_seconds(), 1)})
            prev = (ts, ip)
        if rapid_switch_gap_seconds is not None and len(hop_ips) <= max_ips:
            continue
        norm_counts = Counter(
            normalize_path(raw_path_without_query(r.get("path"))) for _, r in recent
        )
        top = max(norm_counts.values())
        endpoint = sorted(p for p, c in norm_counts.items() if c == top)[0]
        used = len(hop_ips) if rapid_switch_gap_seconds is not None else len(ips)
        reason = (
            f"Credential fingerprint {fp[:8]}... used from {len(ips)} different IPs "
            f"in {window_seconds}s (threshold: {max_ips})"
        )
        if rapid_switch_gap_seconds is not None:
            reason += (
                f"; {hops} switches between {used} IPs within {rapid_switch_gap_seconds}s "
                f"of the previous request (concurrent use)"
            )
        risk = _score_escalated(scorer, "token_replay", reason, used / max(max_ips, 1), "", endpoint)
        findings.append(
            {
                "detection_type": "token_replay",
                "endpoint": endpoint,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": recent[-1][0].isoformat(),
                "metadata": {
                    **_evidence(recent),
                    "rule_id": "REPLAY-CONCURRENT",
                    "ip_switches": timeline,
                    "auth_types": sorted({str(r.get("auth_type") or "unknown") for _, r in recent}),
                    "rapid_switch_gap_seconds": rapid_switch_gap_seconds,
                    "token_fingerprint": fp,
                    "source": "capture",
                    "distinct_ips": len(ips),
                    "rapid_switch_ips": len(hop_ips),
                    "rapid_switches": hops,
                    "ips": ips,
                    "request_count": len(recent),
                    "window_seconds": window_seconds,
                    "max_ips": max_ips,
                    "breakdown": risk.breakdown,
                    "reasons": risk.reasons,
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
                    "rule_id": "BOLA-CASE",
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
                    "rule_id": "REPLAY-CASE",
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
    ownership: dict | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """Full pipeline: captures -> detectors -> scored, sorted findings.

    - Scraping, BOLA-enumeration and capture-based token-replay findings
      come from ``records`` (capture store).
    - Confirmed BOLA comes from explicit ``bola_cases`` or from ``records``
      matched against operator-supplied ``ownership`` context.
    - Token-replay findings also come from explicit ``token_uses``/``checks``.
    Without context only capture-derived attempt signals are produced; users,
    auth maps and tokens are never invented from traffic.
    ``now`` (naive UTC) pins the live window end; None anchors at each
    actor's latest request. ``scraping_all_windows`` is for scans.
    """
    if not isinstance(records, list):
        records = []
    now = to_utc_naive(now) if now is not None else None
    scorer = RiskScorer()
    findings = analyze_scraping_from_captures(
        records,
        scorer,
        time_window_seconds=time_window_seconds,
        rate_threshold=rate_threshold,
        distinct_threshold=distinct_threshold,
        all_windows=scraping_all_windows,
        now=now,
    )
    findings.extend(
        analyze_credential_rotation_from_captures(records, scorer, now=now, all_windows=scraping_all_windows)
    )
    enumeration = analyze_enumeration_from_captures(records, scorer, now=now)
    findings.extend(enumeration)
    explained = {(f["metadata"]["actor"], f["metadata"]["method"], f["endpoint"]) for f in enumeration}
    findings.extend(analyze_access_denied_from_captures(records, scorer, now=now, exclude=explained))
    findings.extend(analyze_token_replay_from_captures(records, scorer, now=now))
    findings.extend(analyze_unauthorized_access_from_captures(records, ownership, scorer, now=now))
    findings.extend(analyze_anomalies_from_captures(records, scorer, now=now))
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
