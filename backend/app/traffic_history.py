"""Persistent real-traffic history and adaptive, explainable endpoint baselines.

History: one row per (UTC hour, method, normalized endpoint), written in the same SQLite
transaction as each captured request (``storage.save_captured_request``), so it survives
restarts and outlives raw-capture retention. It holds counts only: requests, status
classes, response sizes taken from the response ``Content-Length`` (``response_sized``
counts how many had one) and distinct callers. Never headers, tokens, bodies or query
values; a caller is the keyed credential fingerprint, else the client IP (as in captures).

Baselines are learned from those buckets, never from benchmark data. Evidence a baseline
needs before it is trusted (EVIDENCE): at least MIN_DAYS distinct UTC days, MIN_SPAN_HOURS
between the first and last bucket and MIN_BUCKETS active hours, all outside quarantine. One
burst therefore can never make a baseline ready. A bucket is quarantined when it overlaps an
alert on that endpoint (unless the alert was marked ``ignored``) or exceeded the trusted
baseline; quarantined buckets are never learned. Learning (``learn_baselines``, run by
POST /api/scan) stores a new trusted baseline only when the evidence is met, otherwise the
last trusted one is kept. Reads never write.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta
from statistics import median

from app.discovery import is_self_route, normalize_path, path_only
from app.timeutil import parse_timestamp, utcnow

SOURCE = "real traffic captured by this Sentinel instance (not synthetic benchmark data)"
MIN_DAYS = 3
MIN_SPAN_HOURS = 48
MIN_BUCKETS = 6
HOUR_OF_DAY_MIN_SAMPLES = 3   # same-hour-of-day profile once that hour was seen on 3 days
DEVIATION_FACTOR = 3.0        # rate: max(3 x median, median + 3 x 1.4826 x MAD, 5), as in runtime_monitor
DEVIATION_FLOOR = 5
ERROR_MIN_REQUESTS = 10       # 5xx share is judged only on at least this many requests
SIZE_FACTOR = 4               # response size: max > 4 x trusted p95 (when sizes are known)
EVIDENCE = {"min_days": MIN_DAYS, "min_span_hours": MIN_SPAN_HOURS, "min_active_hours": MIN_BUCKETS,
            "hour_of_day_profile_after_days": HOUR_OF_DAY_MIN_SAMPLES}

SCHEMA = """
CREATE TABLE IF NOT EXISTS traffic_history (
    bucket_start TEXT NOT NULL,
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    status_2xx INTEGER NOT NULL DEFAULT 0,
    status_3xx INTEGER NOT NULL DEFAULT 0,
    status_4xx INTEGER NOT NULL DEFAULT 0,
    status_5xx INTEGER NOT NULL DEFAULT 0,
    response_sized INTEGER NOT NULL DEFAULT 0,
    response_bytes_sum INTEGER NOT NULL DEFAULT 0,
    response_bytes_max INTEGER NOT NULL DEFAULT 0,
    quarantined INTEGER NOT NULL DEFAULT 0,
    quarantine_reason TEXT,
    PRIMARY KEY (bucket_start, method, endpoint)
);
CREATE TABLE IF NOT EXISTS traffic_history_callers (
    bucket_start TEXT NOT NULL,
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    caller TEXT NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_start, method, endpoint, caller)
);
CREATE INDEX IF NOT EXISTS idx_history_endpoint ON traffic_history (method, endpoint, bucket_start);
CREATE TABLE IF NOT EXISTS endpoint_baselines (
    method TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    trusted TEXT NOT NULL,
    learned_at TEXT NOT NULL,
    PRIMARY KEY (method, endpoint)
);
CREATE TABLE IF NOT EXISTS schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_captured_created ON captured_requests (created_at);
"""


def bucket_of(value) -> str:
    ts = parse_timestamp(value) or utcnow()
    return ts.replace(minute=0, second=0, microsecond=0).isoformat()


def _status_column(status: int) -> str | None:
    return {2: "status_2xx", 3: "status_3xx", 4: "status_4xx", 5: "status_5xx"}.get(int(status or 0) // 100)


def record(conn: sqlite3.Connection, *, method: str, path: str, status_code: int, at,
           caller: str, response_bytes: int | None) -> None:
    """Add one request to its hourly bucket (caller's transaction; idempotent schema)."""
    if is_self_route(path):
        return
    key = (bucket_of(at), method.upper(), normalize_path(path_only(path) or "/"))
    col = _status_column(status_code)
    sized = response_bytes is not None and response_bytes >= 0
    size = int(response_bytes) if sized else 0
    conn.execute("INSERT OR IGNORE INTO traffic_history (bucket_start, method, endpoint) VALUES (?, ?, ?)", key)
    conn.execute(
        f"UPDATE traffic_history SET requests = requests + 1{f', {col} = {col} + 1' if col else ''},"
        " response_sized = response_sized + ?, response_bytes_sum = response_bytes_sum + ?,"
        " response_bytes_max = MAX(response_bytes_max, ?)"
        " WHERE bucket_start = ? AND method = ? AND endpoint = ?", (int(sized), size, size, *key))
    conn.execute("INSERT INTO traffic_history_callers (bucket_start, method, endpoint, caller, requests)"
                 " VALUES (?, ?, ?, ?, 1) ON CONFLICT DO UPDATE SET requests = requests + 1", (*key, caller))


def caller_key(actor_fp: str | None, client_ip: str | None) -> str:
    return f"credential:{actor_fp}" if actor_fp else f"ip:{client_ip or 'unknown'}"


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Create the history tables and backfill them once from existing captures (marked, idempotent)."""
    conn.executescript(SCHEMA)
    if conn.execute("SELECT 1 FROM schema_meta WHERE key = 'history_backfill'").fetchone():
        return
    rows = conn.execute("SELECT method, path, status_code, client_ip, actor_fp, created_at FROM captured_requests"
                        " ORDER BY id").fetchall()
    for method, path, status, ip, fp, created in rows:
        record(conn, method=method, path=path, status_code=status, at=created, caller=caller_key(fp, ip),
               response_bytes=None)  # sizes were never captured before this table existed
    conn.execute("INSERT INTO schema_meta (key, value) VALUES ('history_backfill', ?)",
                 (json.dumps({"rows": len(rows), "at": utcnow().isoformat(timespec="seconds")}),))


def prune_history(conn: sqlite3.Connection, cutoff_bucket: str, apply: bool) -> int:
    n = conn.execute("SELECT COUNT(*) FROM traffic_history WHERE bucket_start < ?", (cutoff_bucket,)).fetchone()[0]
    if apply:
        conn.execute("DELETE FROM traffic_history WHERE bucket_start < ?", (cutoff_bucket,))
        conn.execute("DELETE FROM traffic_history_callers WHERE bucket_start < ?", (cutoff_bucket,))
    return n


# ---------------------------------------------------------------------------------------------
# baselines

def _threshold(values: list[int]) -> tuple[float, float, float]:
    typical = float(median(values))
    mad = float(median([abs(v - typical) for v in values]))
    return typical, mad, max(typical * DEVIATION_FACTOR, typical + 3 * 1.4826 * mad, DEVIATION_FLOOR)


def _p95(values: list[int]) -> int:
    s = sorted(values)
    return s[int(0.95 * (len(s) - 1))] if s else 0


def _load(conn, days: int, now: datetime):
    since = bucket_of(now - timedelta(days=days))
    conn.row_factory = sqlite3.Row
    buckets: dict[tuple, list[dict]] = {}
    for r in conn.execute("SELECT * FROM traffic_history WHERE bucket_start >= ? ORDER BY bucket_start", (since,)):
        buckets.setdefault((r["method"], r["endpoint"]), []).append(dict(r))
    callers: dict[tuple, int] = {}
    for b, m, e, n in conn.execute("SELECT bucket_start, method, endpoint, COUNT(*) FROM traffic_history_callers"
                                   " WHERE bucket_start >= ? GROUP BY 1, 2, 3", (since,)):
        callers[(b, m, e)] = n
    trusted = {(r["method"], r["endpoint"]): {**json.loads(r["trusted"]), "learned_at": r["learned_at"]}
               for r in conn.execute("SELECT * FROM endpoint_baselines")}
    return buckets, callers, trusted


def _alert_hours(alerts: list[dict]) -> dict[tuple, list[tuple[str, str, int, str]]]:
    """(method or '', endpoint) -> [(first_hour, last_hour, alert_id, type)] for non-ignored alerts."""
    out: dict[tuple, list] = {}
    for a in alerts or []:
        if a.get("status") == "ignored":
            continue  # an analyst marked it a false positive: not evidence of abuse
        md = a.get("metadata") or {}
        first = bucket_of(md.get("first_seen") or a["first_seen"])
        last = bucket_of(a["last_seen"])
        out.setdefault((str(md.get("method") or "").upper(), a["endpoint"]), []).append(
            (first, last, a["id"], a["detection_type"]))
    return out


def _alert_reason(alert_hours, method, endpoint, bucket) -> str | None:
    for key in ((method, endpoint), ("", endpoint)):
        for first, last, aid, dtype in alert_hours.get(key, []):
            if first <= bucket <= last:
                return f"overlaps alert #{aid} ({dtype})"
    return None


def _learnable(rows, alert_hours, method, endpoint, trusted):
    """Split earlier buckets into learnable and quarantined (with reasons)."""
    ok, quarantined = [], []
    for r in rows:
        reason = r["quarantine_reason"] if r["quarantined"] else _alert_reason(alert_hours, method, endpoint, r["bucket_start"])
        if reason is None and trusted:
            limit = trusted["hour_of_day_thresholds"].get(str(int(r["bucket_start"][11:13])), trusted["threshold"])
            if r["requests"] > limit:
                reason = f"{r['requests']} requests exceeded the trusted baseline threshold {limit:g}"
        (quarantined if reason else ok).append((r, reason))
    return [r for r, _ in ok], quarantined


def _evidence(rows) -> tuple[dict, list[str]]:
    days = sorted({r["bucket_start"][:10] for r in rows})
    span = 0.0
    if rows:
        span = (parse_timestamp(rows[-1]["bucket_start"]) - parse_timestamp(rows[0]["bucket_start"])).total_seconds() / 3600
    have = {"days": len(days), "span_hours": round(span, 1), "active_hours": len(rows)}
    unmet = []
    if len(days) < MIN_DAYS:
        unmet.append(f"traffic on {len(days)} of {MIN_DAYS} required days")
    if span < MIN_SPAN_HOURS:
        unmet.append(f"{have['span_hours']:g} of {MIN_SPAN_HOURS} required hours between first and last observation")
    if len(rows) < MIN_BUCKETS:
        unmet.append(f"{len(rows)} of {MIN_BUCKETS} required active hours")
    return have, unmet


def _candidate(rows, callers, method, endpoint) -> dict:
    counts = [r["requests"] for r in rows]
    typical, mad, threshold = _threshold(counts)
    by_hour: dict[int, list[int]] = {}
    for r in rows:
        by_hour.setdefault(int(r["bucket_start"][11:13]), []).append(r["requests"])
    hourly = {h: round(_threshold(v)[2], 2) for h, v in by_hour.items() if len(v) >= HOUR_OF_DAY_MIN_SAMPLES}
    sizes = [r["response_bytes_max"] for r in rows if r["response_sized"]]
    total = sum(counts)
    return {"median_requests_per_active_hour": typical, "mad": round(mad, 2), "threshold": round(threshold, 2),
            "hour_of_day_thresholds": {str(h): t for h, t in sorted(hourly.items())},
            "server_error_share": round(sum(r["status_5xx"] for r in rows) / total, 4) if total else 0.0,
            "response_bytes_p95": _p95(sizes) if sizes else None,
            "median_callers_per_active_hour": float(median(callers.get((r["bucket_start"], method, endpoint), 0) for r in rows)),
            "buckets_used": len(rows), "days_covered": len({r["bucket_start"][:10] for r in rows}),
            "first_bucket": rows[0]["bucket_start"], "last_bucket": rows[-1]["bucket_start"]}


def _judge_current(cur, trusted, hour) -> tuple[bool, list[str], float]:
    threshold = trusted["hour_of_day_thresholds"].get(str(hour), trusted["threshold"])
    reasons = []
    if cur["requests"] > threshold:
        reasons.append(f"{cur['requests']} requests this hour exceed the threshold {threshold:g}")
    if cur["requests"] >= ERROR_MIN_REQUESTS:
        share = cur["status_5xx"] / cur["requests"]
        if share >= max(0.5, trusted["server_error_share"] + 0.3):
            reasons.append(f"5xx share {share:.0%} vs baseline {trusted['server_error_share']:.0%}")
    p95 = trusted.get("response_bytes_p95")
    if p95 and cur["response_sized"] and cur["response_bytes_max"] > SIZE_FACTOR * p95:
        reasons.append(f"largest response {cur['response_bytes_max']} bytes vs baseline p95 {p95}")
    return bool(reasons), reasons, threshold


def evaluate(conn: sqlite3.Connection, alerts: list[dict], *, now: datetime | None = None,
             days: int = 30, persist: bool = False) -> dict:
    """State, confidence and explanation for every endpoint with history. ``persist`` (scan only)
    stores quarantine flags and newly trusted baselines; it never deletes a trusted baseline."""
    now = now or utcnow()
    current = bucket_of(now)
    buckets, callers, stored = _load(conn, days, now)
    alert_hours = _alert_hours(alerts)
    items = []
    # Endpoints with a stored trusted baseline stay visible even when retention removed their history.
    for method, endpoint in sorted(set(buckets) | set(stored)):
        rows = buckets.get((method, endpoint), [])
        earlier = [r for r in rows if r["bucket_start"] < current]
        cur = next((r for r in rows if r["bucket_start"] == current), None)
        trusted = stored.get((method, endpoint))
        learnable, quarantined = _learnable(earlier, alert_hours, method, endpoint, trusted)
        have, unmet = _evidence(learnable)
        learned_now = None
        if not unmet:
            learned_now = _candidate(learnable, callers, method, endpoint)
            if persist:
                conn.execute("INSERT INTO endpoint_baselines (method, endpoint, trusted, learned_at) VALUES (?, ?, ?, ?)"
                             " ON CONFLICT DO UPDATE SET trusted = excluded.trusted, learned_at = excluded.learned_at",
                             (method, endpoint, json.dumps(learned_now, sort_keys=True), now.isoformat(timespec="seconds")))
                learned_now["learned_at"] = now.isoformat(timespec="seconds")
        if persist:
            for r, reason in quarantined:
                if not r["quarantined"]:
                    conn.execute("UPDATE traffic_history SET quarantined = 1, quarantine_reason = ?"
                                 " WHERE bucket_start = ? AND method = ? AND endpoint = ?",
                                 (reason, r["bucket_start"], method, endpoint))
        baseline = learned_now or trusted
        explanation, deviation_reasons, threshold = [], [], None
        if baseline is None:
            state = "no_baseline" if not earlier else "insufficient"
            confidence = "none"
            explanation.append("No earlier hour of traffic for this endpoint yet." if not earlier else
                               "Not trusted yet: " + "; ".join(unmet) + ".")
        else:
            if learned_now is None:
                explanation.append(f"Using the last trusted baseline (learned {trusted.get('learned_at')}); "
                                   "recent evidence does not yet support a new one: " + "; ".join(unmet) + ".")
            profile = "same hour of day" if str(int(current[11:13])) in baseline["hour_of_day_thresholds"] else "all active hours"
            deviates, deviation_reasons, threshold = (_judge_current(cur, baseline, int(current[11:13]))
                                                      if cur else (False, [], baseline["threshold"]))
            state = "deviation" if deviates else "ready"
            confidence = "high" if baseline["days_covered"] >= 7 and profile == "same hour of day" else "moderate"
            explanation.append(f"Baseline from {baseline['buckets_used']} active hours over {baseline['days_covered']} days "
                               f"({profile}); threshold {threshold:g} requests per hour.")
            explanation.extend(deviation_reasons)
            if persist and deviates:
                conn.execute("UPDATE traffic_history SET quarantined = 1, quarantine_reason = ?"
                             " WHERE bucket_start = ? AND method = ? AND endpoint = ?",
                             ("; ".join(deviation_reasons), current, method, endpoint))
        if quarantined:
            explanation.append(f"{len(quarantined)} hour(s) quarantined and not learned "
                               f"({quarantined[-1][1]}{'; ...' if len(quarantined) > 1 else ''}).")
        total = sum(r["requests"] for r in rows)
        items.append({
            "method": method, "endpoint": endpoint, "state": state, "confidence": confidence,
            "explanation": " ".join(explanation), "unmet_requirements": unmet, "evidence": have,
            "observations": total, "first_seen": rows[0]["bucket_start"] if rows else None,
            "last_update": rows[-1]["bucket_start"] if rows else None,
            "span_hours": round((parse_timestamp(rows[-1]["bucket_start"]) - parse_timestamp(rows[0]["bucket_start"])).total_seconds() / 3600, 1) if rows else 0,
            "active_hours": len(rows), "quarantined_hours": len(quarantined),
            "baseline": baseline, "current_hour": {"bucket": current, "requests": cur["requests"] if cur else 0,
                                                   "threshold": threshold, "deviation_reasons": deviation_reasons},
            "trend": [{"bucket": r["bucket_start"], "requests": r["requests"],
                       "quarantined": bool(r["quarantined"]) or any(r is q for q, _ in quarantined)} for r in rows[-24:]],
        })
    return {"source": SOURCE, "generated_at": now.isoformat(timespec="seconds"), "window_days": days,
            "evidence_required": EVIDENCE, "endpoints": items}
