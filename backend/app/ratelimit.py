"""Per-endpoint rate limiting with a VP quota of exactly 21x the normal limit.

Endpoint = ``METHOD /route/template`` (e.g. ``PATCH /api/alerts/{alert_id}``,
or ``GET /gateway/shop/orders/{id}`` for gateway routes). Every endpoint has
its own limit: built-in defaults below, overridable per endpoint through
SENTINEL_RATE_LIMITS_PATH. Unknown endpoint names in the file are a startup
error, so a typo cannot silently leave an endpoint on the default.

Identity is decided server-side only (``resolve_identity``), in this order:
1. a credential whose keyed fingerprint is a registered principal
   (``app/principals.py``) -> its own bucket and its role (``user``/``vp``);
2. a valid ``X-Sentinel-Key`` -> the ``admin`` bucket (normal quota);
3. anything else -> the client address (IPv6 grouped by /64). Unregistered
   credentials are ignored for bucketing, so rotating made-up tokens or
   adding headers cannot open fresh buckets.
Headers such as ``X-Role: vp`` are never read for identity; they are only
logged as an ignored privilege claim.

Window: fixed, aligned to multiples of ``window_seconds`` since the Unix
epoch (default 60 s). A client can therefore make up to 2x its limit across
one window boundary; Retry-After is the time to the next boundary.
Counters live in this process's memory and one lock makes check-and-count
atomic. Several worker processes or hosts each keep their own counters: run
one process or put a shared store (not implemented) in front.
"""

import hmac
import ipaddress
import logging
import math
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone

from fastapi import HTTPException, Request, Response

from app.capture import GATEWAY_PREFIX, credential_fingerprint
from app.principals import Principal

VP_MULTIPLIER = 21  # fixed by policy: VP quota = 21 x the endpoint's normal quota
DEFAULT_WINDOW_SECONDS = 60
DEFAULT_LIMIT = 60
MAX_LIMIT = 100_000  # normal quota cap per window (VP cap = 2.1 million)
# Anonymous (IP) buckets per window; when full, *new* IP buckets are refused
# (429) rather than left unlimited. Principals and admin are always tracked.
MAX_IP_BUCKETS = 100_000
UNMATCHED_GATEWAY_ENDPOINT = "ANY /gateway/* (no matching route)"

# Per-window defaults, chosen from what each route costs and how the demo uses it.
DEFAULT_LIMITS = {
    "GET /api/health": 120,           # cheap; probes and dashboard polling
    "GET /api/inventory": 60,         # reads all captures
    "GET /api/shadow-apis": 30,       # also reads a spec file
    "GET /api/findings": 60,
    "GET /api/alerts": 60,
    "PATCH /api/alerts/{alert_id}": 30,
    "POST /api/scan": 10,             # most expensive: analyses every capture
    "GET /api/rate-limits": 30,
    "GET /api/gateway-events": 60,
    # Deliberately vulnerable demo shop: high enough that the simulator's
    # attack scenarios (<= 40 requests per client) still reach the detectors.
    "GET /shop/products/{product_id}": 300,
    "GET /shop/me": 120,
    "GET /shop/orders/{order_id}": 120,
    "GET /shop/internal/export": 60,
    "GET /shop/admin/stats": 60,
}

# Caller-supplied headers that *claim* identity or privilege. Never trusted.
CLAIM_HEADERS = ("x-role", "x-user-role", "x-user", "x-user-id", "x-vp", "x-privileged",
                 "x-forwarded-user", "x-remote-user", "x-auth-user", "x-sentinel-role")

log = logging.getLogger("api_sentinel.ratelimit")


@dataclass(frozen=True)
class RateLimitConfig:
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    default_limit: int = DEFAULT_LIMIT
    overrides: Mapping[str, int] | None = None

    @classmethod
    def from_dict(cls, data: object) -> "RateLimitConfig":
        if data is None:
            return cls()
        if not isinstance(data, dict) or set(data) - {"window_seconds", "default_limit", "limits"}:
            raise ValueError("rate limits must be an object with window_seconds, default_limit, limits")
        window = data.get("window_seconds", DEFAULT_WINDOW_SECONDS)
        default = data.get("default_limit", DEFAULT_LIMIT)
        limits = data.get("limits", {})
        if not _int_in(window, 1, 86_400):
            raise ValueError("window_seconds must be an integer from 1 to 86400")
        if not _int_in(default, 1, MAX_LIMIT):
            raise ValueError(f"default_limit must be an integer from 1 to {MAX_LIMIT}")
        if not isinstance(limits, dict):
            raise ValueError("limits must be an object of 'METHOD /path': integer")
        for key, value in limits.items():
            if not _int_in(value, 1, MAX_LIMIT):
                raise ValueError(f"limit for {key!r} must be an integer from 1 to {MAX_LIMIT}")
        return cls(window, default, dict(limits))


def _int_in(value: object, low: int, high: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


@dataclass(frozen=True)
class Identity:
    kind: str                       # "principal" | "admin" | "ip"
    key: str                        # bucket key
    principal: Principal | None = None
    client_ip: str = ""

    @property
    def role(self) -> str:
        return self.principal.role if self.principal else "user"

    @property
    def purpose(self) -> str:
        return self.principal.purpose if self.principal else "normal"


def client_bucket(host: str | None) -> str:
    """IPv4 as-is; IPv6 grouped by /64 (one subscriber usually owns a whole /64)."""
    try:
        ip = ipaddress.ip_address(host or "")
    except ValueError:
        return f"ip:{host or 'unknown'}"
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return f"ip:{ip.ipv4_mapped}"
        return f"ip:{ipaddress.ip_network(f'{ip}/64', strict=False)}"
    return f"ip:{ip}"


def resolve_identity(headers: Mapping[str, str], client_host: str | None,
                     principals: Mapping[str, Principal], fp_key: bytes | None,
                     admin_key: bytes | None) -> Identity:
    """Server-side identity; see the module docstring for the order."""
    ip = client_host or "unknown"
    fp = credential_fingerprint(headers, fp_key) if principals else None
    principal = principals.get(fp) if fp else None
    if principal is not None:
        return Identity("principal", f"principal:{principal.id}", principal, ip)
    given = headers.get("x-sentinel-key")
    if admin_key is not None and given and hmac.compare_digest(given.encode(), admin_key):
        return Identity("admin", "admin", None, ip)
    return Identity("ip", client_bucket(ip), None, ip)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after: int
    window_start: float


class RateLimiter:
    """Fixed-window counters per (endpoint, identity); thread-safe."""

    def __init__(self, config: RateLimitConfig, clock: Callable[[], float] | None = None):
        self.config = config
        self.clock = clock or time.time
        self.limits = {**DEFAULT_LIMITS, **(config.overrides or {})}
        self._lock = threading.Lock()
        self._window_id: int | None = None
        self._counts: dict[tuple[str, str], int] = {}
        self._ip_buckets = 0

    def normal_limit(self, endpoint: str) -> int:
        return self.limits.get(endpoint, self.config.default_limit)

    def limit_for(self, endpoint: str, role: str) -> int:
        base = self.normal_limit(endpoint)
        return base * VP_MULTIPLIER if role == "vp" else base

    def validate_endpoints(self, known: set[str]) -> None:
        unknown = sorted(set(self.config.overrides or {}) - known)
        if unknown:
            raise ValueError(f"rate limits configured for unknown endpoints: {unknown}")

    def check(self, endpoint: str, identity: Identity) -> Decision:
        limit = self.limit_for(endpoint, identity.role)
        window = self.config.window_seconds
        now = self.clock()
        window_id = math.floor(now / window)
        retry_after = max(1, math.ceil((window_id + 1) * window - now))
        key = (endpoint, identity.key)
        with self._lock:
            if window_id != self._window_id:  # new window: every old counter expired
                self._window_id, self._counts, self._ip_buckets = window_id, {}, 0
            count = self._counts.get(key)
            if count is None and identity.kind == "ip":
                if self._ip_buckets >= MAX_IP_BUCKETS:
                    return Decision(False, limit, 0, retry_after, window_id * window)
                self._ip_buckets += 1
            count = count or 0
            if count >= limit:
                return Decision(False, limit, 0, retry_after, window_id * window)
            self._counts[key] = count + 1
        return Decision(True, limit, limit - count - 1, retry_after, window_id * window)


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def record_event(state, *, endpoint: str, identity: Identity, decision: str, reason: str,
                 status_code: int, window_start: float | None = None) -> None:
    """Audit row + log line. Never includes credentials, paths' query values or bodies."""
    from app.storage import save_gateway_event  # avoid an import cycle at module load

    now = state.rate_limiter.clock()
    window = state.rate_limiter.config.window_seconds
    start = window_start if window_start is not None else math.floor(now / window) * window
    principal_id = identity.principal.id if identity.principal else ""
    log.info("access_control decision=%s reason=%s status=%d endpoint=%s identity=%s principal=%s role=%s purpose=%s",
             decision, reason, status_code, endpoint, identity.kind, principal_id or "-",
             identity.role, identity.purpose)
    try:
        save_gateway_event(state.db_path, window_start=iso(start), seen_at=iso(now), endpoint=endpoint,
                           decision=decision, reason=reason, status_code=status_code,
                           identity_kind=identity.kind, principal_id=principal_id,
                           role=identity.role, purpose=identity.purpose, client_ip=identity.client_ip)
    except Exception:
        log.warning("could not store access-control event (decision=%s)", decision)


def apply_limit(state, endpoint: str, identity: Identity, headers: Mapping[str, str],
                response: Response | None = None) -> Decision:
    """Count one request; raise 429 when over quota. Also writes the audit trail."""
    decision = state.rate_limiter.check(endpoint, identity)
    if identity.role != "vp" and any(h in headers for h in CLAIM_HEADERS):
        record_event(state, endpoint=endpoint, identity=identity, decision="ignored",
                     reason="unverified_privilege_claim", status_code=0,
                     window_start=decision.window_start)
    limit_headers = {"X-RateLimit-Limit": str(decision.limit),
                     "X-RateLimit-Remaining": str(decision.remaining)}
    if not decision.allowed:
        record_event(state, endpoint=endpoint, identity=identity, decision="rate_limited",
                     reason="quota_exceeded", status_code=429, window_start=decision.window_start)
        raise HTTPException(status_code=429, detail="rate limit exceeded for this endpoint",
                            headers={**limit_headers, "Retry-After": str(decision.retry_after)})
    if identity.role == "vp" or identity.purpose != "normal":
        record_event(state, endpoint=endpoint, identity=identity, decision="allowed",
                     reason="vp_quota" if identity.role == "vp" else identity.purpose,
                     status_code=0, window_start=decision.window_start)
    if response is not None:
        response.headers.update(limit_headers)
    return decision


def current_identity(request: Request) -> Identity:
    st = request.app.state
    return resolve_identity(request.headers, request.client.host if request.client else None,
                            st.principals, st.fp_key, st.api_key)


def enforce_rate_limit(request: Request, response: Response) -> None:
    """App-wide dependency: limit every routed Sentinel/demo endpoint.

    Runs after routing (so the route template is known) and before the
    route's own auth, so failed-key guessing is limited too. Gateway routes
    are limited inside the gateway handler (one catch-all route, many endpoints).
    """
    template = getattr(request.scope.get("route"), "path", None)
    if template is None or template.startswith(GATEWAY_PREFIX):
        return
    method = "GET" if request.method == "HEAD" else request.method
    apply_limit(request.app.state, f"{method} {template}", current_identity(request),
                request.headers, response)
