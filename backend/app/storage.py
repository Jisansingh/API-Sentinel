"""SQLite storage initialization (standard library only).

We use ``sqlite3`` from the standard library to keep this foundation
step beginner-friendly and dependency-free.

Privacy rule: the table stores only safe request summaries (method,
path, status code, timing, keyed credential fingerprint). It NEVER stores
headers, bodies, raw tokens, or passwords.
"""

import json
import sqlite3
from pathlib import Path

from app.discovery import is_self_route
from app.timeutil import parse_timestamp
from app.traffic_history import caller_key, ensure_schema as ensure_history_schema, record as record_history

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captured_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    actor_fp TEXT,
    auth_type TEXT NOT NULL DEFAULT 'unknown',
    payload_bytes INTEGER NOT NULL DEFAULT 0
);
"""

# Persistent alerts, one row per (detection_type, actor, endpoint).
# Written only by POST /api/scan; metadata holds safe finding metadata only.
_ALERTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detection_type TEXT NOT NULL,
    actor TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    reason TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'open',
    note TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    occurrences INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (detection_type, actor, endpoint)
);
"""


# Access-control audit trail (rate limiting, gateway firewall, privileged use).
# One row per (window, endpoint, decision, reason, identity) with a counter, so a
# flood adds to ``count`` instead of adding rows. Never holds credentials, raw
# paths, query values or bodies: endpoints are route templates.
_GATEWAY_EVENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS gateway_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    identity_kind TEXT NOT NULL,
    principal_id TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL DEFAULT '',
    purpose TEXT NOT NULL DEFAULT '',
    client_ip TEXT NOT NULL DEFAULT '',
    count INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (window_start, endpoint, decision, reason, identity_kind, principal_id, client_ip)
);
"""


# Phase 5. Endpoint risk history: a row is written (by POST /api/scan and alert triage) only
# when an endpoint's score or factor contributions differ from its latest row, so history
# holds genuine changes and is never reconstructed after the fact.
_RISK_SNAPSHOTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoint_risk_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    score INTEGER NOT NULL,
    factors TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""
# Incidents group related alerts: same category, same caller (and, for endpoint-wide
# anomalies, same endpoint), with no gap longer than INCIDENT_GAP_SECONDS between them.
# Alerts keep their own ids, evidence and status; they only gain an incident_id.
_INCIDENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category TEXT NOT NULL,
    actor TEXT NOT NULL,
    endpoint_scope TEXT NOT NULL DEFAULT '',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
"""
INCIDENT_GAP_SECONDS = 3600


def init_db(db_path: str | Path) -> Path:
    """Create the SQLite file and tables if they do not exist yet."""
    path = Path(db_path)
    if str(path) != ":memory:" and path.parent != Path(".") and str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        conn.execute(_SCHEMA)
        conn.execute(_ALERTS_SCHEMA)
        conn.execute(_GATEWAY_EVENTS_SCHEMA)
        conn.execute(_RISK_SNAPSHOTS_SCHEMA)
        conn.execute(_INCIDENTS_SCHEMA)
        if "incident_id" not in {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}:
            conn.execute("ALTER TABLE alerts ADD COLUMN incident_id INTEGER")
        # Alerts stored before incidents existed are grouped once, oldest first (deterministic).
        for alert_id, dtype, actor, endpoint, first, last in conn.execute(
            "SELECT id, detection_type, actor, endpoint, first_seen, last_seen FROM alerts"
            " WHERE incident_id IS NULL ORDER BY first_seen, id"
        ).fetchall():
            _assign_incident(conn, alert_id, dtype, actor, endpoint, first, last)
        # Additive migration for databases created before actor_fp existed.
        columns = {row[1] for row in conn.execute("PRAGMA table_info(captured_requests)")}
        if "actor_fp" not in columns:
            conn.execute("ALTER TABLE captured_requests ADD COLUMN actor_fp TEXT")
        if "auth_type" not in columns:
            conn.execute("ALTER TABLE captured_requests ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'unknown'")
        if "payload_bytes" not in columns:
            conn.execute("ALTER TABLE captured_requests ADD COLUMN payload_bytes INTEGER NOT NULL DEFAULT 0")
        ensure_history_schema(conn)  # additive tables + index; one-time, marked backfill from captures
        conn.commit()
    return path


def save_captured_request(
    db_path: str | Path,
    *,
    method: str,
    path: str,
    status_code: int,
    duration_ms: float,
    client_ip: str = "",
    actor_fp: str | None = None,
    auth_type: str = "unknown",
    payload_bytes: int = 0,
    created_at: str | None = None,
    response_bytes: int | None = None,
) -> int:
    """Persist one sanitized request summary. Returns the new row id.

    ``created_at`` (``YYYY-MM-DD HH:MM:SS`` UTC) is for deterministic
    fixtures; normal capture lets SQLite stamp the current UTC time.
    """
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "INSERT INTO captured_requests"
            " (method, path, status_code, duration_ms, client_ip, actor_fp, auth_type, payload_bytes, created_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))",
            (method, path, status_code, duration_ms, client_ip, actor_fp, auth_type, max(0, int(payload_bytes)), created_at),
        )
        # Same transaction: the hourly history and the raw capture are written together or not at all.
        record_history(conn, method=method, path=path, status_code=status_code, at=created_at,
                       caller=caller_key(actor_fp, client_ip), response_bytes=response_bytes)
        conn.commit()
        return int(cursor.lastrowid)


def count_captured_requests(db_path: str | Path) -> int:
    """Return how many request summaries are stored (helper for tests)."""
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()
        return int(row[0]) if row else 0


def fetch_captured_requests(
    db_path: str | Path, include_internal: bool = False
) -> list[dict]:
    """Return sanitized capture records as dicts (oldest first).

    Read-only. Rows for Sentinel's own routes (``/docs``, ``/openapi.json``,
    ...) are hidden unless ``include_internal``: older databases may hold
    them from before capture skipped those routes, and they must not show up
    as client traffic or shadow APIs. Nothing is deleted.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT method, path, status_code, duration_ms, client_ip, created_at, actor_fp, auth_type, payload_bytes"
            " FROM captured_requests ORDER BY id ASC"
        ).fetchall()
        records = [dict(row) for row in rows]
    if include_internal:
        return records
    return [r for r in records if not is_self_route(r["path"])]


_ALERT_COLUMNS = (
    "id, detection_type, actor, endpoint, risk_score, reason, metadata, status,"
    " note, first_seen, last_seen, occurrences, incident_id"
)


def _assign_incident(conn, alert_id, detection_type, actor, endpoint, first_seen, last_seen) -> int:
    """Attach an alert to the latest incident of its group if within the gap, else open one."""
    from app.analysis import ALL_CALLERS, CATEGORIES  # lazy: analysis does not import storage

    category = CATEGORIES.get(detection_type, detection_type)
    scope = endpoint if actor == ALL_CALLERS else ""
    row = conn.execute(
        "SELECT id, last_seen FROM incidents WHERE category = ? AND actor = ? AND endpoint_scope = ?"
        " ORDER BY last_seen DESC, id DESC LIMIT 1", (category, actor, scope)).fetchone()
    start, end = parse_timestamp(first_seen), parse_timestamp(row[1]) if row else None
    if row and start and end and (start - end).total_seconds() <= INCIDENT_GAP_SECONDS:
        incident_id = row[0]
        if _is_newer(last_seen, row[1]):
            conn.execute("UPDATE incidents SET last_seen = ? WHERE id = ?", (last_seen, incident_id))
    else:
        incident_id = conn.execute(
            "INSERT INTO incidents (category, actor, endpoint_scope, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (category, actor, scope, first_seen, last_seen)).lastrowid
    conn.execute("UPDATE alerts SET incident_id = ? WHERE id = ?", (incident_id, alert_id))
    return incident_id


def _alert_row(row: sqlite3.Row) -> dict:
    alert = dict(row)
    alert["metadata"] = json.loads(alert["metadata"] or "{}")
    return alert


def _canonical_ts(value) -> str:
    """Store timestamps as naive-UTC ISO strings (the existing stored format)."""
    parsed = parse_timestamp(value)
    return parsed.isoformat() if parsed else str(value)


def _is_newer(candidate: str, stored: str) -> bool:
    """Compare as UTC datetimes; unparseable values fall back to string order."""
    new, old = parse_timestamp(candidate), parse_timestamp(stored)
    if new is None or old is None:
        return str(candidate) > str(stored)
    return new > old


def upsert_alerts(db_path: str | Path, alerts: list[dict]) -> dict:
    """Insert or refresh alerts; returns created/updated/unchanged counts.

    Each alert dict needs detection_type, actor, endpoint, risk_score,
    reason, timestamp, metadata. Dedup key is (detection_type, actor,
    endpoint). A finding whose timestamp is not newer than the stored
    ``last_seen`` is the same evidence re-scanned and changes nothing. Newer
    evidence bumps ``occurrences`` and reopens a ``resolved`` alert;
    ``ignored`` and ``acknowledged`` keep their status.
    """
    counts = {"created": 0, "updated": 0, "unchanged": 0}
    with sqlite3.connect(str(db_path)) as conn:
        for a in alerts:
            a = {**a, "timestamp": _canonical_ts(a["timestamp"])}
            key = (a["detection_type"], a["actor"], a["endpoint"])
            row = conn.execute(
                "SELECT id, last_seen FROM alerts"
                " WHERE detection_type = ? AND actor = ? AND endpoint = ?",
                key,
            ).fetchone()
            metadata = json.dumps(a["metadata"], sort_keys=True, default=str)
            if row is None:
                first = a["timestamp"]  # the evidence's own start is metadata.first_seen
                cursor = conn.execute(
                    "INSERT INTO alerts (detection_type, actor, endpoint, risk_score,"
                    " reason, metadata, first_seen, last_seen)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (*key, a["risk_score"], a["reason"], metadata,
                     first, a["timestamp"]),
                )
                _assign_incident(conn, cursor.lastrowid, *key, first, a["timestamp"])
                counts["created"] += 1
            elif _is_newer(a["timestamp"], row[1]):
                conn.execute(
                    "UPDATE alerts SET risk_score = ?, reason = ?, metadata = ?,"
                    " last_seen = ?, occurrences = occurrences + 1,"
                    " status = CASE status WHEN 'resolved' THEN 'open' ELSE status END,"
                    " updated_at = datetime('now') WHERE id = ?",
                    (a["risk_score"], a["reason"], metadata, a["timestamp"], row[0]),
                )
                conn.execute(
                    "UPDATE incidents SET last_seen = ? WHERE id = (SELECT incident_id FROM alerts WHERE id = ?)"
                    " AND last_seen < ?", (a["timestamp"], row[0], a["timestamp"]))
                counts["updated"] += 1
            else:
                counts["unchanged"] += 1
        conn.commit()
    return counts


def list_alerts(db_path: str | Path, status: str | None = None) -> list[dict]:
    """Return stored alerts, most recently seen first."""
    query = f"SELECT {_ALERT_COLUMNS} FROM alerts"
    params: tuple = ()
    if status:
        query += " WHERE status = ?"
        params = (status,)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query + " ORDER BY last_seen DESC, risk_score DESC, id ASC", params).fetchall()
        return [_alert_row(r) for r in rows]


def update_alert_status(
    db_path: str | Path, alert_id: int, status: str, note: str | None
) -> dict | None:
    """Set an alert's status (and note); returns the alert or None if missing."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "UPDATE alerts SET status = ?, note = COALESCE(?, note),"
            " updated_at = datetime('now') WHERE id = ?",
            (status, note, alert_id),
        )
        conn.commit()
        if cursor.rowcount == 0:
            return None
        row = conn.execute(
            f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        return _alert_row(row)


def get_alert(db_path: str | Path, alert_id: int) -> dict | None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(f"SELECT {_ALERT_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    return _alert_row(row) if row else None


def list_incidents(db_path: str | Path) -> list[dict]:
    """Incidents with their alert ids, newest activity first (read-only)."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        incidents = [dict(r) for r in conn.execute(
            "SELECT id, category, actor, endpoint_scope, first_seen, last_seen FROM incidents"
            " ORDER BY last_seen DESC, id DESC").fetchall()]
        members: dict[int, list] = {}
        for r in conn.execute("SELECT id, incident_id, detection_type, endpoint, status, risk_score"
                              " FROM alerts WHERE incident_id IS NOT NULL ORDER BY id").fetchall():
            members.setdefault(r["incident_id"], []).append(
                {k: r[k] for k in ("id", "detection_type", "endpoint", "status", "risk_score")})
    for inc in incidents:
        alerts = members.get(inc["id"], [])
        inc.update(alerts=alerts, alert_ids=[a["id"] for a in alerts],
                   max_risk_score=max((a["risk_score"] for a in alerts), default=0),
                   open_alerts=sum(a["status"] in ("open", "acknowledged") for a in alerts))
    return incidents


def latest_risk_snapshots(db_path: str | Path, limit: int = 2) -> dict[tuple, list[dict]]:
    """Up to ``limit`` most recent snapshots per (method, path), newest first."""
    out: dict[tuple, list[dict]] = {}
    with sqlite3.connect(str(db_path)) as conn:
        for method, path, score, factors, created_at in conn.execute(
            "SELECT method, path, score, factors, created_at FROM endpoint_risk_snapshots"
            " ORDER BY id DESC").fetchall():
            snaps = out.setdefault((method, path), [])
            if len(snaps) < limit:
                snaps.append({"score": score, "factors": json.loads(factors), "created_at": created_at})
    return out


def save_risk_snapshots(db_path: str | Path, views: list[tuple[str, str, dict]], at: str) -> int:
    """Store (method, path, snapshot_view) rows that differ from the endpoint's latest one."""
    latest = latest_risk_snapshots(db_path, limit=1)
    written = 0
    with sqlite3.connect(str(db_path)) as conn:
        for method, path, view in views:
            prev = latest.get((method, path))
            if prev and prev[0]["score"] == view["score"] and prev[0]["factors"] == view["factors"]:
                continue
            conn.execute("INSERT INTO endpoint_risk_snapshots (method, path, score, factors, created_at)"
                         " VALUES (?, ?, ?, ?, ?)", (method, path, view["score"],
                                                     json.dumps(view["factors"], sort_keys=True), at))
            written += 1
        conn.commit()
    return written


def save_gateway_event(db_path: str | Path, *, window_start: str, seen_at: str, endpoint: str,
                       decision: str, reason: str, status_code: int, identity_kind: str,
                       principal_id: str = "", role: str = "", purpose: str = "",
                       client_ip: str = "") -> None:
    """Count one access-control event in its (window, endpoint, decision, identity) row."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO gateway_events (window_start, endpoint, decision, reason, status_code,"
            " identity_kind, principal_id, role, purpose, client_ip, first_seen, last_seen)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT (window_start, endpoint, decision, reason, identity_kind, principal_id, client_ip)"
            " DO UPDATE SET count = count + 1, last_seen = excluded.last_seen,"
            " status_code = excluded.status_code",
            (window_start, endpoint, decision, reason, status_code, identity_kind,
             principal_id, role, purpose, client_ip, seen_at, seen_at),
        )
        conn.commit()


def list_gateway_events(db_path: str | Path, limit: int = 200) -> list[dict]:
    """Most recent access-control events first (read-only)."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, window_start, endpoint, decision, reason, status_code, identity_kind,"
            " principal_id, role, purpose, client_ip, count, first_seen, last_seen"
            " FROM gateway_events ORDER BY last_seen DESC, id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]
