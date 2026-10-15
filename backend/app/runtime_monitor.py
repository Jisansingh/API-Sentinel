"""Runtime telemetry and peak-aware endpoint baselines.

Only metadata is analyzed. Request bodies and credential values are never read.
Rates are compared with the same hour-of-week for the endpoint, so a normal
weekday peak is not treated as an anomaly merely because it is busier than night.
"""
from __future__ import annotations

import sqlite3
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from statistics import median
from typing import Any

from app.discovery import normalize_path
from app.timeutil import parse_timestamp


def _timestamp(value: Any) -> datetime | None:
    parsed = parse_timestamp(value)
    if parsed is None:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _actor(record: dict) -> str:
    # Fingerprint is keyed and non-reversible; don't expose IP or credential material
    # as a stable caller ID when a credential fingerprint exists.
    return f"credential:{record['actor_fp']}" if record.get("actor_fp") else f"ip:{record.get('client_ip') or 'unknown'}"


def build_runtime_baselines(records: list[dict], *, now: datetime | None = None,
                            days: int = 30, min_history_buckets: int = 3) -> dict:
    """Summarize endpoint and caller behavior with same-hour-of-week comparisons."""
    now = now or datetime.utcnow()
    if now.tzinfo is not None:
        now = now.astimezone(timezone.utc).replace(tzinfo=None)
    cutoff = now - timedelta(days=max(1, min(90, days)))
    parsed_records = []
    for raw in records:
        ts = _timestamp(raw.get("created_at"))
        if ts is None or ts < cutoff or ts > now + timedelta(minutes=5):
            continue
        path = normalize_path(str(raw.get("path", "/")).split("?", 1)[0])
        method = str(raw.get("method", "GET")).upper()
        try:
            status = int(raw.get("status_code", 0))
        except (ValueError, TypeError):
            status = 0
        try:
            size = max(0, int(raw.get("payload_bytes", 0) or 0))
        except (ValueError, TypeError):
            size = 0
        parsed_records.append({**raw, "_ts": ts, "_endpoint": f"{method} {path}",
                               "_status": status, "_size": size, "_actor": _actor(raw)})

    # Bucket by endpoint/caller/hour; counts naturally handle peaks that recur
    # at the same hour-of-week. The baseline compares only matching weekday/hour.
    endpoint_buckets: dict[tuple[str, str], int] = defaultdict(int)
    caller_buckets: dict[tuple[str, str, str], int] = defaultdict(int)
    endpoint_records: dict[str, list[dict]] = defaultdict(list)
    caller_records: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for rec in parsed_records:
        ts = rec["_ts"]
        hour = ts.replace(minute=0, second=0, microsecond=0)
        endpoint_buckets[(rec["_endpoint"], hour.isoformat())] += 1
        caller_buckets[(rec["_endpoint"], rec["_actor"], hour.isoformat())] += 1
        endpoint_records[rec["_endpoint"]].append(rec)
        caller_records[(rec["_endpoint"], rec["_actor"])].append(rec)

    current_hour = now.replace(minute=0, second=0, microsecond=0)
    def rate_summary(endpoint: str, actor: str | None = None) -> dict:
        rows = endpoint_records.get(endpoint, []) if actor is None else caller_records.get((endpoint, actor), [])
        current_count = sum(1 for r in rows if r["_ts"] >= current_hour)
        # Hour-of-week historical comparison excludes the current hour.
        history = []
        for offset in range(1, max(1, days * 24)):
            hour = current_hour - timedelta(hours=offset)
            if hour.weekday() == current_hour.weekday() and hour.hour == current_hour.hour:
                key = (endpoint, hour.isoformat()) if actor is None else (endpoint, actor, hour.isoformat())
                bucket_map = endpoint_buckets if actor is None else caller_buckets
                # Only a bucket with observed endpoint/caller traffic counts as
                # a historical sample; unseen periods are not assumed to be zero.
                if key in bucket_map:
                    history.append(bucket_map[key])
        history = history[-max(1, days // 7):]
        typical = float(median(history)) if history else 0.0
        deviations = [abs(v - typical) for v in history]
        mad = float(median(deviations)) if deviations else 0.0
        threshold = max(typical * 3.0, typical + 3.0 * 1.4826 * mad, 5.0)
        enough = len(history) >= min_history_buckets
        anomalous = enough and current_count > threshold
        return {"current_hour_requests": current_count,
                "baseline_median_requests": round(typical, 2),
                "baseline_samples": len(history),
                "rate_anomaly": bool(anomalous),
                "rate_anomaly_reason": ("Current rate exceeds same-hour-of-week baseline" if anomalous else None),
                "rate_alert_suppressed_reason": ("insufficient matching historical buckets" if not enough else None)}

    endpoint_results = []
    for endpoint, rows in sorted(endpoint_records.items()):
        statuses = [r["_status"] for r in rows]
        sizes = [r["_size"] for r in rows]
        errors = sum(1 for status in statuses if status >= 500)
        last_seen = max(r["_ts"] for r in rows)
        result = {"endpoint": endpoint, "request_count": len(rows),
                  "requests_per_hour_observed": round(len(rows) / max(1, min(days * 24, (now-cutoff).total_seconds()/3600)), 3),
                  "payload_bytes_mean": round(sum(sizes) / len(sizes), 2),
                  "payload_bytes_max": max(sizes, default=0),
                  "server_error_rate": round(errors / len(rows), 4),
                  "last_seen": last_seen.isoformat() + "Z"}
        result.update(rate_summary(endpoint))
        endpoint_results.append(result)

    caller_results = []
    for (endpoint, actor), rows in sorted(caller_records.items()):
        result = {"endpoint": endpoint, "caller": actor, "request_count": len(rows),
                  "payload_bytes_mean": round(sum(r["_size"] for r in rows) / len(rows), 2),
                  "server_error_rate": round(sum(1 for r in rows if r["_status"] >= 500) / len(rows), 4)}
        result.update(rate_summary(endpoint, actor))
        caller_results.append(result)

    # Do not emit a rate alert if the only evidence is a higher total than other
    # time periods. The baseline explicitly compares equivalent weekday/hour slots.
    return {"window_days": max(1, min(90, days)), "generated_at": now.isoformat() + "Z",
            "requests_analyzed": len(parsed_records), "endpoints": endpoint_results,
            "callers": caller_results,
            "baseline_method": "median of matching weekday/hour buckets; rate alert requires at least "
                               f"{min_history_buckets} matching historical buckets"}


def fetch_runtime_records(db_path: str) -> list[dict]:
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT method,path,status_code,client_ip,actor_fp,auth_type,payload_bytes,created_at "
                            "FROM captured_requests ORDER BY id ASC").fetchall()
    return [dict(row) for row in rows]
