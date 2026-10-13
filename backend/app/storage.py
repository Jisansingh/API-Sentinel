"""SQLite storage initialization (standard library only).

We use ``sqlite3`` from the standard library to keep this foundation
step beginner-friendly and dependency-free.

Privacy rule: the table stores only safe request summaries (method,
path, status code, timing). It NEVER stores headers, bodies, tokens,
or passwords.
"""

import sqlite3
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS captured_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    duration_ms REAL NOT NULL,
    client_ip TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def init_db(db_path: str | Path) -> Path:
    """Create the SQLite file and tables if they do not exist yet."""
    path = Path(db_path)
    if str(path) != ":memory:" and path.parent != Path(".") and str(path.parent):
        path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(path)) as conn:
        conn.execute(_SCHEMA)
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
) -> int:
    """Persist one sanitized request summary. Returns the new row id."""
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "INSERT INTO captured_requests"
            " (method, path, status_code, duration_ms, client_ip)"
            " VALUES (?, ?, ?, ?, ?)",
            (method, path, status_code, duration_ms, client_ip),
        )
        conn.commit()
        return int(cursor.lastrowid)


def count_captured_requests(db_path: str | Path) -> int:
    """Return how many request summaries are stored (helper for tests)."""
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()
        return int(row[0]) if row else 0


def fetch_captured_requests(db_path: str | Path) -> list[dict]:
    """Return all sanitized capture records as dicts (oldest first).

    Added for the discovery/inventory feature. Read-only; the table schema
    is unchanged, so existing code and tests keep working.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT method, path, status_code, duration_ms, client_ip, created_at"
            " FROM captured_requests ORDER BY id ASC"
        ).fetchall()
        return [dict(row) for row in rows]
