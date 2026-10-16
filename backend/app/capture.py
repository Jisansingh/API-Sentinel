"""Safe HTTP request-capture middleware.

What it records per request (safe summary only):
  method, path (query secrets redacted), status code, duration, client IP,
  and a keyed HMAC fingerprint of the Authorization/X-API-Key value.

What it NEVER records:
  request/response bodies, raw tokens, passwords, API keys, cookies,
  or Authorization headers. We deliberately do not even read the body,
  so sensitive payloads can never leak into storage or logs.
"""

import hashlib
import hmac
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.discovery import SELF_ROUTE_PREFIXES, is_self_route  # noqa: F401  (re-exported)
from app.storage import save_captured_request

REDACTED = "[REDACTED]"
GATEWAY_PREFIX = "/gateway"  # app.gateway imports this module, so the prefix lives here too

# Header names (lowercased) whose values must never be stored.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "api-key",
        "x-auth-token",
        "x-access-token",
    }
)

# Query parameter names (lowercased) whose values must be redacted.
SENSITIVE_QUERY_PARAMS = frozenset(
    {
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "api_key",
        "apikey",
        "client_secret",
        "password",
        "secret",
    }
)


# Credential headers whose value identifies the caller (fingerprinted, never stored).
CREDENTIAL_HEADERS = ("authorization", "x-api-key")

# Sentinel's own routes (see discovery.SELF_ROUTE_PREFIXES): capturing them would make
# dashboard polling and health checks look like client traffic.


def classify_authentication(headers: Mapping[str, Any]) -> str:
    """Classify credential mechanism without retaining credential material."""
    if headers.get("authorization"):
        value = str(headers.get("authorization", "")).split(None, 1)[0].lower()
        return {"bearer": "bearer", "basic": "basic"}.get(value, "authorization-header")
    if headers.get("x-api-key") or headers.get("api-key"):
        return "api-key"
    if headers.get("cookie"):
        return "session-cookie"
    if headers.get("x-auth-token") or headers.get("x-access-token"):
        return "token-header"
    return "none"


def credential_fingerprint(headers: Mapping[str, Any], secret: bytes | None) -> str | None:
    """Keyed HMAC-SHA256 of the first credential header, or None.

    Keyed (not plain SHA-256) so a leaked database cannot be used to confirm
    guessed tokens offline. Returns None without a secret or a credential;
    callers then fall back to the client IP as the actor.
    """
    if not secret:
        return None
    for name in CREDENTIAL_HEADERS:
        value = headers.get(name)
        if value:
            return hmac.new(secret, str(value).encode(), hashlib.sha256).hexdigest()[:32]
    return None


def sanitize_headers(headers: Mapping[str, Any]) -> dict[str, str]:
    """Return headers with sensitive values replaced by ``[REDACTED]``."""
    clean: dict[str, str] = {}
    for name, value in headers.items():
        if str(name).lower() in SENSITIVE_HEADERS:
            clean[str(name)] = REDACTED
        else:
            clean[str(name)] = str(value)
    return clean


def sanitize_path(path: str) -> str:
    """Redact sensitive query-string values, keeping path structure.

    Example: ``/api/u?token=abc&next=/x`` -> ``/api/u?token=[REDACTED]&next=/x``.
    A plain path without a query string is returned unchanged.
    """
    if "?" not in path:
        return path
    parts = urlsplit(path)
    if not parts.query:
        return path
    redacted_pairs = [
        (k, REDACTED if k.lower() in SENSITIVE_QUERY_PARAMS else v)
        for k, v in parse_qsl(parts.query, keep_blank_values=True)
    ]
    return urlunsplit(("", "", parts.path, urlencode(redacted_pairs), ""))


def _response_length(value: Any) -> int | None:
    try:
        size = int(value)
    except (TypeError, ValueError):
        return None
    return size if size >= 0 else None


def _content_length(value: Any) -> int:
    """Parse Content-Length safely; unknown/chunked request bodies are recorded as 0."""
    try:
        parsed = int(str(value))
        return max(0, parsed)
    except (TypeError, ValueError):
        return 0


class RequestCaptureMiddleware(BaseHTTPMiddleware):
    """Record a small safe summary of each request.

    Records are kept in ``self.captured_requests`` (in-memory, handy for
    tests) and optionally persisted to SQLite via ``db_path``. Persistence
    failures are swallowed so monitoring can never break real traffic.
    """

    def __init__(
        self,
        app: Any,
        enabled: bool = True,
        db_path: Any | None = None,
        fp_secret: bytes | None = None,
        strip_gateway_prefix: bool = False,
    ) -> None:
        super().__init__(app)
        self.strip_gateway_prefix = strip_gateway_prefix
        self.enabled = enabled
        self.db_path = db_path
        self.fp_secret = fp_secret
        self.captured_requests: list[dict[str, Any]] = []

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        if not self.enabled or is_self_route(request.url.path):
            return await call_next(request)

        start = time.perf_counter()
        response = await call_next(request)
        duration_ms = (time.perf_counter() - start) * 1000.0
        if getattr(request.state, "skip_capture", False):
            return response  # set by the gateway for requests its firewall refused pre-routing

        # NOTE: we never read/await request.body() here on purpose.
        raw_path = request.url.path
        if self.strip_gateway_prefix and raw_path.startswith(GATEWAY_PREFIX + "/"):
            # Gateway traffic is recorded as the upstream path it targets, so
            # inventory, shadow-API and abuse detection see the protected API.
            raw_path = raw_path[len(GATEWAY_PREFIX):]
        if request.url.query:
            raw_path = f"{raw_path}?{request.url.query}"
        record = {
            "method": request.method,
            "path": sanitize_path(raw_path),
            "status_code": response.status_code,
            "duration_ms": duration_ms,
            "client_ip": request.client.host if request.client else "unknown",
            "actor_fp": credential_fingerprint(request.headers, self.fp_secret),
            "auth_type": classify_authentication(request.headers),
            # Header-only estimate; deliberately never consume the request body.
            "payload_bytes": _content_length(request.headers.get("content-length")),
        }
        self.captured_requests.append(record)

        if self.db_path is not None:
            try:
                save_captured_request(
                    self.db_path,
                    method=record["method"],
                    path=record["path"],
                    status_code=record["status_code"],
                    duration_ms=record["duration_ms"],
                    client_ip=record["client_ip"],
                    actor_fp=record["actor_fp"],
                    auth_type=record["auth_type"],
                    payload_bytes=record["payload_bytes"],
                    # Response size from the response header only (None when not sent, e.g. streamed).
                    response_bytes=_response_length(response.headers.get("content-length")),
                )
            except Exception:
                # Monitoring must never break the request path.
                pass
        return response
