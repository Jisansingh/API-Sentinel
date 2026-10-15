"""Controlled reverse proxy / API firewall in front of ONE configured upstream.

Enabled only with a gateway config (SENTINEL_GATEWAY_CONFIG or
``create_app(gateway=...)``). Clients call ``/gateway/<upstream path>``; only
routes listed in the config are forwarded::

    {"upstream": "https://api.internal.example:8443",
     "allow_private_network": false,
     "routes": [
       {"method": "GET", "path": "/shop/products/{id}", "auth": "none"},
       {"method": "GET", "path": "/shop/orders/{id}", "auth": "principal", "roles": ["user", "vp"]}
     ]}

Protections (each one has a test in tests/test_gateway.py):
- Upstream fixed by the operator: scheme http/https, host, port. The client
  supplies only path segments (validated, then rebuilt) and a query string,
  so it can never choose another host, port or scheme.
- SSRF / DNS rebinding: the host is resolved per request, *every* address must
  pass ``address_allowed`` and the socket connects to that checked address
  (TLS still verifies the configured hostname). Link-local and cloud-metadata
  addresses are always refused; loopback/private ones only with
  ``allow_private_network``; plain http only to non-public addresses.
- Redirects are never followed (3xx from upstream -> 502).
- Method + path-template allowlist, strict path charset (no encoded slashes,
  dots-only segments, backslashes), URL/header/body size caps, connect and
  overall timeouts, response size cap, header allowlists both ways, generic
  error bodies (upstream 5xx bodies are not passed through).
- Per-endpoint rate limits and the VP quota (app/ratelimit.py) before auth;
  ``auth: principal`` routes need a registered principal with an allowed role.
  A VP is checked exactly like everyone else; only the quota differs.
Traffic still flows through Sentinel's capture middleware (recorded under the
upstream path, without the /gateway prefix) so inventory, shadow-API and abuse
detection, risk scoring and alerts see it.
"""

import http.client
import ipaddress
import json
import re
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, Response
from starlette.exceptions import HTTPException

from app.capture import GATEWAY_PREFIX
from app.principals import ROLES
from app.ratelimit import UNMATCHED_GATEWAY_ENDPOINT, apply_limit, current_identity, record_event

METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
MAX_URL_BYTES = 2048
MAX_HEADER_BYTES = 16 * 1024
MAX_HEADER_COUNT = 64
_SEGMENT = re.compile(r"^[A-Za-z0-9._~-]{1,128}$")
_TEMPLATE = re.compile(r"^(/([A-Za-z0-9._~-]+|\{[a-z_][a-z0-9_]{0,31}\}))+$")
_QUERY = re.compile(r"^[\x21-\x7e]*$")  # printable ASCII, no spaces or controls
_ENCODED_BAD = re.compile(rb"%(2f|5c|2e|00)", re.IGNORECASE)
REDIRECTS = {301, 302, 303, 307, 308}
FORWARD_REQUEST_HEADERS = ("accept", "accept-language", "content-type", "authorization",
                           "x-api-key", "user-agent")
FORWARD_RESPONSE_HEADERS = ("content-type", "cache-control", "etag", "last-modified",
                            "content-language", "retry-after", "www-authenticate")
# Cloud metadata endpoints outside the link-local range (which is always refused).
METADATA_ADDRESSES = {ipaddress.ip_address(a) for a in
                      ("100.100.100.200", "fd00:ec2::254", "192.0.0.192")}


@dataclass(frozen=True)
class Route:
    method: str
    path: str
    segments: tuple[str, ...]
    auth: str
    roles: tuple[str, ...]

    @property
    def endpoint(self) -> str:
        return f"{self.method} {GATEWAY_PREFIX}{self.path}"

    def matches(self, method: str, segments: list[str]) -> bool:
        return method == self.method and len(segments) == len(self.segments) and all(
            t.startswith("{") or t == s for t, s in zip(self.segments, segments))


@dataclass(frozen=True)
class GatewayConfig:
    scheme: str
    host: str
    port: int
    allow_private_network: bool
    routes: tuple[Route, ...]
    connect_timeout: float = 3.0
    total_timeout: float = 10.0
    max_request_body: int = 1024 * 1024
    max_response_body: int = 5 * 1024 * 1024

    @property
    def endpoints(self) -> set[str]:
        return {r.endpoint for r in self.routes} | {UNMATCHED_GATEWAY_ENDPOINT}

    @property
    def needs_principals(self) -> bool:
        return any(r.auth == "principal" for r in self.routes)


def _number(data: dict, key: str, default: float, low: float, high: float) -> float:
    value = data.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise ValueError(f"gateway {key} must be a number from {low} to {high}")
    return value


def parse_gateway_config(data: object) -> GatewayConfig:
    """Validate a gateway config dict; raise ValueError (never echoing secrets)."""
    allowed = {"upstream", "allow_private_network", "routes", "connect_timeout_seconds",
               "total_timeout_seconds", "max_request_body_bytes", "max_response_body_bytes"}
    if not isinstance(data, dict) or set(data) - allowed:
        raise ValueError(f"gateway config must be an object with keys {sorted(allowed)}")
    url = data.get("upstream")
    if not isinstance(url, str):
        raise ValueError("gateway upstream must be a URL string")
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("gateway upstream must be http(s)://host[:port]")
    if parts.username or parts.password or parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ValueError("gateway upstream must not contain credentials, a path, query or fragment")
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        raise ValueError("gateway upstream port is invalid") from None
    private = data.get("allow_private_network", False)
    if not isinstance(private, bool):
        raise ValueError("allow_private_network must be true or false")
    try:  # a literal IP is checked now; hostnames are checked on every request
        literal = ipaddress.ip_address(parts.hostname)
    except ValueError:
        literal = None
    if literal is not None and not address_allowed(literal, parts.scheme, private):
        raise ValueError("gateway upstream address is not allowed (see allow_private_network)")
    routes, seen = [], set()
    raw_routes = data.get("routes")
    if not isinstance(raw_routes, list) or not 1 <= len(raw_routes) <= 500:
        raise ValueError("gateway routes must be a list of 1 to 500 routes")
    for i, r in enumerate(raw_routes):
        if not isinstance(r, dict) or set(r) - {"method", "path", "auth", "roles"}:
            raise ValueError(f"gateway route #{i}: keys are method, path, auth, roles")
        method, path, auth = r.get("method"), r.get("path"), r.get("auth", "principal")
        if method not in METHODS:
            raise ValueError(f"gateway route #{i}: method must be one of {METHODS}")
        if not isinstance(path, str) or len(path) > 512 or not _TEMPLATE.match(path) or "/../" in path + "/" \
                or any(seg in (".", "..") for seg in path.split("/")):
            raise ValueError(f"gateway route #{i}: path must look like /a/{{id}} (letters, digits, ._~-)")
        if auth not in ("principal", "none"):
            raise ValueError(f"gateway route #{i}: auth must be 'principal' or 'none'")
        roles = r.get("roles", list(ROLES) if auth == "principal" else [])
        if auth == "none" and roles:
            raise ValueError(f"gateway route #{i}: roles only apply to auth 'principal' routes")
        if auth == "principal" and (not isinstance(roles, list) or not roles or set(roles) - set(ROLES)):
            raise ValueError(f"gateway route #{i}: roles must be a non-empty subset of {ROLES}")
        if (method, path) in seen:
            raise ValueError(f"gateway route #{i}: duplicate {method} {path}")
        seen.add((method, path))
        routes.append(Route(method, path, tuple(path.strip("/").split("/")), auth, tuple(roles)))
    return GatewayConfig(
        parts.scheme, parts.hostname, port, private, tuple(routes),
        _number(data, "connect_timeout_seconds", 3.0, 0.1, 30),
        _number(data, "total_timeout_seconds", 10.0, 0.1, 120),
        int(_number(data, "max_request_body_bytes", 1024 * 1024, 0, 50 * 1024 * 1024)),
        int(_number(data, "max_response_body_bytes", 5 * 1024 * 1024, 1, 100 * 1024 * 1024)),
    )


def load_gateway_config(path: str | Path) -> GatewayConfig:
    try:
        data = json.loads(Path(path).read_text())
    except (OSError, ValueError) as err:
        raise ValueError(f"cannot read gateway config: {type(err).__name__}") from None
    return parse_gateway_config(data)


def address_allowed(ip: ipaddress.IPv4Address | ipaddress.IPv6Address, scheme: str,
                    allow_private: bool) -> bool:
    """SSRF policy for one resolved upstream address."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if ip in METADATA_ADDRESSES or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_loopback:  # before is_reserved: Python counts ::1 as reserved (::/8)
        return allow_private
    if ip.is_reserved:
        return False
    if not ip.is_global:  # loopback, RFC 1918, ULA, CGNAT, documentation ranges...
        return allow_private
    return scheme == "https"  # public upstreams only over TLS


def resolve_host(host: str, port: int) -> list[str]:
    """All addresses for host (separate function so tests can substitute DNS)."""
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(info[4][0] for info in infos))


class UpstreamRefused(Exception):
    """The upstream address failed the SSRF policy."""


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, ip, connect_timeout, timeout):
        super().__init__(host, port, timeout=timeout)
        self._ip, self._connect_timeout = ip, connect_timeout

    def connect(self):
        self.sock = socket.create_connection((self._ip, self.port), self._connect_timeout)
        self.sock.settimeout(self.timeout)


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, port, ip, connect_timeout, timeout):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip, self._connect_timeout = ip, connect_timeout

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self._connect_timeout)
        sock.settimeout(self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)  # verifies the name


def forward(cfg: GatewayConfig, method: str, target: str, headers: dict, body: bytes):
    """Blocking upstream call. Returns (status, headers, body); raises on policy/timeout."""
    addresses = resolve_host(cfg.host, cfg.port)
    checked = [ipaddress.ip_address(a.split("%")[0]) for a in addresses]
    if not checked or not all(address_allowed(ip, cfg.scheme, cfg.allow_private_network) for ip in checked):
        raise UpstreamRefused()
    deadline = time.monotonic() + cfg.total_timeout
    conn_cls = _PinnedHTTPS if cfg.scheme == "https" else _PinnedHTTP
    conn = conn_cls(cfg.host, cfg.port, str(checked[0]), cfg.connect_timeout, cfg.total_timeout)
    try:
        conn.request(method, target, body=body or None, headers=headers)
        resp = conn.getresponse()
        chunks, size = [], 0
        while chunk := resp.read(65536):
            size += len(chunk)
            if size > cfg.max_response_body:
                raise OverflowError()
            if time.monotonic() > deadline:
                raise TimeoutError()
            chunks.append(chunk)
        return resp.status, resp.getheaders(), b"".join(chunks)
    finally:
        conn.close()


router = APIRouter()


def _deny(state, identity, endpoint: str, status: int, reason: str, detail: str) -> JSONResponse:
    record_event(state, endpoint=endpoint, identity=identity, decision="blocked",
                 reason=reason, status_code=status)
    return JSONResponse({"detail": detail}, status_code=status)


@router.api_route(GATEWAY_PREFIX + "/{_path:path}", methods=list(METHODS), include_in_schema=False)
async def gateway(request: Request, _path: str) -> Response:
    state = request.app.state
    cfg: GatewayConfig = state.gateway
    identity = current_identity(request)
    raw_path = request.scope.get("raw_path") or request.scope["path"].encode()
    query = request.scope.get("query_string", b"")
    unmatched = UNMATCHED_GATEWAY_ENDPOINT

    def limited(endpoint: str):
        """Count the request; a 429 response when over quota, else the decision."""
        try:
            return apply_limit(state, endpoint, identity, request.headers)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, status_code=429, headers=exc.headers)

    # Anything that is not a configured route (oversized, malformed, unknown)
    # counts against one per-identity quota before it is refused.
    header_bytes = sum(len(k) + len(v) for k, v in request.headers.raw)
    sub = raw_path[len(GATEWAY_PREFIX):]
    segments = sub.decode("ascii", "replace").strip("/").split("/")
    problem = None
    if len(request.headers.raw) > MAX_HEADER_COUNT or header_bytes > MAX_HEADER_BYTES:
        problem = (431, "headers_too_large", "request headers too large")
    elif len(raw_path) + len(query) > MAX_URL_BYTES:
        problem = (414, "url_too_long", "request URL too long")
    elif (not sub.startswith(b"/") or b"//" in sub or b"\\" in sub or _ENCODED_BAD.search(sub)
            or sub.endswith(b"/") or not all(_SEGMENT.match(s) and s not in (".", "..") for s in segments)
            or not _QUERY.match(query.decode("latin-1"))):
        problem = (400, "invalid_path", "request path not allowed")
    route = None if problem else next((r for r in cfg.routes if r.matches(request.method, segments)), None)
    if route is None:
        outcome = limited(unmatched)
        if isinstance(outcome, Response):
            return outcome
        if problem is None:
            if any(r.matches(m, segments) for r in cfg.routes for m in METHODS):
                problem = (405, "method_not_allowed", "method not allowed")
            else:
                problem = (404, "route_not_allowed", "route not found")
        # Not an upstream route: keep it out of captured traffic (inventory/shadow
        # APIs would otherwise list attacker-chosen paths); the event log has it.
        request.state.skip_capture = True
        return _deny(state, identity, unmatched, *problem)

    endpoint = route.endpoint
    decision = limited(endpoint)
    if isinstance(decision, Response):
        return decision

    if route.auth == "principal":
        if identity.kind != "principal":
            return _deny(state, identity, endpoint, 401, "auth_required", "authentication required")
        if identity.role not in route.roles:
            return _deny(state, identity, endpoint, 403, "role_forbidden", "not allowed for this role")

    declared = request.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > cfg.max_request_body):
        return _deny(state, identity, endpoint, 413, "body_too_large", "request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > cfg.max_request_body:
            return _deny(state, identity, endpoint, 413, "body_too_large", "request body too large")

    port = "" if cfg.port == (443 if cfg.scheme == "https" else 80) else f":{cfg.port}"
    out_headers = {k: v for k in FORWARD_REQUEST_HEADERS if (v := request.headers.get(k))}
    out_headers.update({"Host": f"{cfg.host}{port}",
                        "X-Forwarded-For": identity.client_ip,  # overwrite, never append
                        "Accept-Encoding": "identity"})
    target = "/" + "/".join(segments) + (f"?{query.decode('ascii')}" if query else "")
    try:
        status, resp_headers, resp_body = await run_in_threadpool(
            forward, cfg, request.method, target, out_headers, bytes(body))
    except UpstreamRefused:
        return _deny(state, identity, endpoint, 502, "upstream_address_refused", "upstream not allowed")
    except (TimeoutError, socket.timeout):
        return _deny(state, identity, endpoint, 504, "upstream_timeout", "upstream timed out")
    except OverflowError:
        return _deny(state, identity, endpoint, 502, "response_too_large", "upstream response too large")
    except (OSError, http.client.HTTPException):
        return _deny(state, identity, endpoint, 502, "upstream_unavailable", "upstream unavailable")
    if status in REDIRECTS:
        return _deny(state, identity, endpoint, 502, "upstream_redirect", "upstream redirect refused")
    if status >= 500:
        return JSONResponse({"detail": "upstream error"}, status_code=status)
    keep = {k: v for k, v in resp_headers if k.lower() in FORWARD_RESPONSE_HEADERS}
    keep.update({"X-RateLimit-Limit": str(decision.limit),
                 "X-RateLimit-Remaining": str(decision.remaining)})
    return Response(resp_body, status_code=status, headers=keep)
