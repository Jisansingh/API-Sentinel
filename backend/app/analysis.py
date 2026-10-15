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
    now: datetime | None = None,
) -> list[dict]:
    """Flag BOLA-style object-ID probing from captured traffic alone.

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
        groups[key].append((ts, ids, rec.get("status_code", 0)))

    findings: list[dict] = []
    for (actor, method, template), entries in sorted(groups.items()):
        recent = _in_window(entries, window_seconds, now)
        if not recent:
            continue
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
                    "reasons": risk.reasons,
                },
            }
        )
    return findings


def analyze_unauthorized_access_from_captures(
    records: list[dict],
    ownership: dict | None,
    scorer: RiskScorer | None = None,
    *,
    now: datetime | None = None,
    window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
) -> list[dict]:
    """Confirmed BOLA: a successful read of an object owned by someone else.

    Needs operator-supplied ownership context (never inferred from traffic)::

        {"resources": {"/shop/orders/{id}": {"1": "alice", "2": "bob"}},
         "actors": {"<actor_fp or client_ip>": "alice"}}

    A 2xx response to an ID-bearing template whose owner is known, from an
    actor mapped to a different user, is flagged. Requests from unmapped
    actors or for unmapped objects are ignored (no context => no claim).
    This proves the server returned another user's object; it is only as
    accurate as the supplied context.
    """
    if not ownership:
        return []
    resources = ownership.get("resources") or {}
    users = ownership.get("actors") or {}
    if scorer is None:
        scorer = RiskScorer()
    hits: dict[tuple, list[tuple[datetime, str, str]]] = defaultdict(list)
    actor_types: dict[str, str] = {}
    for ts, rec in _timed_records(records):
        status = rec.get("status_code", 0)
        if not isinstance(status, int) or not 200 <= status < 300:
            continue
        raw_path = raw_path_without_query(rec.get("path"))
        template = normalize_path(raw_path)
        owners = resources.get(template)
        ids = id_segments(raw_path)
        if not owners or not ids:
            continue
        actor, actor_type = _actor(rec)
        user = users.get(actor)
        owner = owners.get("/".join(ids))
        if user and owner and owner != user:
            actor_types[actor] = actor_type
            hits[(actor, str(rec.get("method", "")).upper(), template)].append(
                (ts, "/".join(ids), owner)
            )

    findings: list[dict] = []
    for (actor, method, template), entries in sorted(hits.items()):
        recent = _in_window(entries, window_seconds, now)
        if not recent:
            continue
        objects = {obj for _, obj, _ in recent}
        user = users[actor]
        reason = (
            f"User {user} successfully read {len(objects)} object(s) owned by other users "
            f"on {method} {template} - confirmed BOLA (broken object-level authorization)"
        )
        risk = _score_escalated(scorer, "bola", reason, len(objects), method, template)
        findings.append(
            {
                "detection_type": "bola",
                "endpoint": template,
                "risk_score": risk.score,
                "reason": reason,
                "timestamp": recent[-1][0].isoformat(),
                "metadata": {
                    "actor": actor,
                    "actor_type": actor_types[actor],
                    "user_id": user,
                    "method": method,
                    "unauthorized_objects": len(objects),
                    "request_count": len(recent),
                    "source": "ownership_context",
                    "breakdown": risk.breakdown,
                    "reasons": risk.reasons,
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
        prev: tuple[datetime, str] | None = None
        for ts, r in recent:
            ip = str(r.get("client_ip") or "unknown")
            if prev and ip != prev[1] and (
                rapid_switch_gap_seconds is None
                or (ts - prev[0]).total_seconds() <= rapid_switch_gap_seconds
            ):
                hop_ips.update((ip, prev[1]))
                hops += 1
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
    findings.extend(analyze_enumeration_from_captures(records, scorer, now=now))
    findings.extend(analyze_token_replay_from_captures(records, scorer, now=now))
    findings.extend(analyze_unauthorized_access_from_captures(records, ownership, scorer, now=now))
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
