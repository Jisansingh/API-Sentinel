"""Timestamp normalization: every time Sentinel compares is naive UTC.

SQLite's ``datetime('now')`` is UTC without a zone, and stored findings/alerts
already use naive ISO strings, so the canonical form stays naive-UTC (no
history is rewritten). Zone-aware inputs are converted to UTC first; naive
inputs are assumed to already be UTC.
"""

from datetime import datetime, timezone
from typing import Any

_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f")


def to_utc_naive(value: datetime) -> datetime:
    """Convert a datetime to naive UTC (naive input is assumed UTC)."""
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def utcnow() -> datetime:
    """Current time as naive UTC (the one clock the app uses by default)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def parse_timestamp(value: Any) -> datetime | None:
    """Parse a datetime or string into naive UTC; None if missing/malformed."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return to_utc_naive(value)
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    for fmt in _FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        # Accept UTC's Z suffix on Python 3.10 as well as newer versions.
        normalized = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        return to_utc_naive(datetime.fromisoformat(normalized))
    except ValueError:
        return None
