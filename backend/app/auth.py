"""Authentication for Sentinel's own API (not the monitored traffic).

Clients send the admin key in ``X-Sentinel-Key`` (compared in constant time).
- SENTINEL_API_KEY set: every Sentinel route except /api/health needs it.
- Not set (local dev): reads stay open, writes are refused (fail closed).
"""

import hmac

from fastapi import Header, HTTPException, Request

KEY_HEADER = "X-Sentinel-Key"


def _check(expected: bytes, provided: str | None) -> None:
    if not provided or not hmac.compare_digest(provided.encode(), expected):
        raise HTTPException(
            status_code=401,
            detail=f"missing or invalid {KEY_HEADER}",
            headers={"WWW-Authenticate": KEY_HEADER},
        )


def require_read(
    request: Request, x_sentinel_key: str | None = Header(default=None)
) -> None:
    """Reads: key required only when one is configured."""
    expected = request.app.state.api_key
    if expected is not None:
        _check(expected, x_sentinel_key)


def require_write(
    request: Request, x_sentinel_key: str | None = Header(default=None)
) -> None:
    """Writes (scan, alert triage): always need a configured, matching key."""
    expected = request.app.state.api_key
    if expected is None:
        raise HTTPException(
            status_code=503,
            detail="SENTINEL_API_KEY is not configured; write endpoints are disabled",
        )
    _check(expected, x_sentinel_key)
