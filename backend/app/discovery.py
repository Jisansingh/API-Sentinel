"""API discovery: path normalization, inventory building, OpenAPI comparison.

Beginner-friendly pure functions (no FastAPI/SQLite imports here), so they
are easy to unit-test. Privacy rule: we aggregate already-sanitized capture
records — method, path, status, timing. We use query-parameter NAMES only,
never values, and never touch bodies, tokens, or passwords.
"""

import json
import re

try:
    import yaml  # PyYAML: supports OpenAPI YAML files
except ImportError:  # JSON support remains available without the optional parser
    yaml = None
# A malformed spec must yield the generic "parse failed" answer on both parsers; YAML's
# errors are not ValueError subclasses and their messages quote the file's content.
_SPEC_PARSE_ERRORS = (json.JSONDecodeError, UnicodeDecodeError, RecursionError, ValueError) + (
    (yaml.YAMLError,) if yaml is not None else ())
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

# A segment that is only digits: /users/101, /orders/2024, ...
_NUMERIC_SEGMENT = re.compile(r"^[0-9]+$")  # ASCII only: \d would match other scripts

# UUID-like segments: 8-4-4-4-12 hex (with dashes) or 32 hex chars.
_UUID_SEGMENT = re.compile(
    r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})$"
)

# A route that only ever answered with these never resolved to a real
# operation (scanner probes, typos). Same default idea as Wallarm
# api-firewall's shadow-API exclude list (404).
UNRESOLVED_STATUSES = frozenset({404, 405})

# Sentinel's own routes: never client traffic, so never inventory/shadow noise.
SELF_ROUTE_PREFIXES = (
    "/api/health",
    "/api/inventory",
    "/api/shadow-apis",
    "/api/findings",
    "/api/alerts",
    "/api/scan",
    "/api/rate-limits",
    "/api/gateway-events",
    "/api/evaluation",
    "/api/source-scan",          # also covers /api/source-scan/upload (whole-segment match)
    "/api/source-apis",
    "/api/runtime/baselines",
    "/api/runtime/history",
    "/api/risk",
    "/api/incidents",
    "/api/proxy-status",         # answered by the dashboard proxy; older proxies forwarded it here
    "/docs",
    "/redoc",
    "/openapi.json",
)

# Largest OpenAPI file we will parse (a bigger file is almost certainly not a spec).
MAX_SPEC_BYTES = 2 * 1024 * 1024

# OpenAPI path-template placeholder: /users/{id}, /users/{userId}, ...
_SPEC_PLACEHOLDER = re.compile(r"\{[^}/]+\}")


def path_only(path: str) -> str:
    """The path part of a request target, without query or fragment.

    Not ``urlsplit(path).path``: a target such as ``//users/5`` would be read
    as host ``users`` and lose a segment.
    """
    return re.split(r"[?#]", str(path), maxsplit=1)[0]


def is_self_route(path: str) -> bool:
    """True for Sentinel's own routes (whole-segment prefix match)."""
    path = path_only(path)
    return any(path == p or path.startswith(p + "/") for p in SELF_ROUTE_PREFIXES)


def _strip_trailing_slash(path: str) -> str:
    """Remove single trailing slash, leaving root unmodified."""
    if len(path) > 1 and path.endswith("/"):
        return path.rstrip("/")
    return path


def _is_resource_id(segment: str) -> bool:
    """Return True only for conservative resource-ID shapes.

    Deliberately narrow (digits or UUID-like) so distinct static endpoints
    such as ``/users/search`` are never merged into ``/users/{id}``.
    """
    return bool(
        _NUMERIC_SEGMENT.match(segment)
        or _UUID_SEGMENT.match(segment)
    )


def path_segments(path: str) -> list[str]:
    """Clean path segments: query dropped, percent-decoded, ``.``/``..`` resolved.

    Decoding per segment keeps ``%2F`` inside a segment from changing the
    path structure; it is re-encoded. Empty segments (``//``) are dropped.
    """
    out: list[str] = []
    for seg in path_only(path).split("/"):
        seg = unquote(seg).replace("/", "%2F")
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return out


def normalize_path(path: str) -> str:
    """Normalize an observed request path into an inventory key.

    - Drops the query string (parameter names are tracked separately).
    - Percent-decodes segments and resolves ``.``/``..`` (``/users/%31`` and
      ``/users/1`` are the same endpoint).
    - Maps numeric / UUID-like segments to ``{id}``.
    - Keeps every other segment exactly as observed.
    - Ignores trailing and duplicate slashes (``/users/`` -> ``/users``).

    Examples:
        ``/users/101`` -> ``/users/{id}``
        ``/users/search`` -> ``/users/search`` (unchanged)
    """
    parts = ["{id}" if _is_resource_id(seg) else seg for seg in path_segments(path)]
    return "/" + "/".join(parts)


def id_segments(path: str) -> tuple[str, ...]:
    """Raw values of the segments that ``normalize_path`` turns into ``{id}``."""
    return tuple(seg for seg in path_segments(path) if _is_resource_id(seg))


def normalize_spec_template(template: str) -> str:
    """Normalize an OpenAPI path template so it compares with observed paths.

    ``/users/{userId}`` -> ``/users/{id}``, matching ``normalize_path`` output.
    """
    raw = _strip_trailing_slash(template if template.startswith("/") else f"/{template}")
    return _SPEC_PLACEHOLDER.sub("{id}", raw)


def extract_query_param_names(path: str) -> list[str]:
    """Return sorted unique query-parameter NAMES from a stored path.

    Only names are returned — values (already redacted at capture time) are
    never read or stored here.
    """
    query = urlsplit(path).query
    if not query:
        return []
    return sorted({name for name, _ in parse_qsl(query, keep_blank_values=True)})


_HIGH_SENSITIVITY = {"password", "passwd", "token", "access_token", "refresh_token", "secret", "ssn", "aadhaar", "pan", "card_number", "cvv", "medical_record", "health_record"}
_MEDIUM_SENSITIVITY = {"email", "phone", "mobile", "address", "dob", "date_of_birth", "user_id", "account_id", "location"}


def sensitivity_basis(path: str, query_params=()) -> str:
    """Why ``classify_data_sensitivity`` chose its level (route/parameter names only, never payloads)."""
    tokens = set(re.findall(r"[a-z0-9]+", (path + " " + " ".join(query_params)).lower()))
    hits = sorted(tokens & (_HIGH_SENSITIVITY | _MEDIUM_SENSITIVITY))
    hits += [part.strip("/") for part in ("/users", "/accounts", "/patients", "/payments") if part in path.lower()]
    if not hits:
        return "no sensitive name observed in the route or parameter names (payloads are never read)"
    return "name heuristic matched: " + ", ".join(sorted(set(hits))) + " (route/parameter names only; payloads are never read)"


def classify_data_sensitivity(path: str, query_params=()) -> str:
    """Heuristic classification from route/parameter names only; never reads payloads."""
    tokens = set(re.findall(r"[a-z0-9]+", (path + " " + " ".join(query_params)).lower()))
    if tokens & _HIGH_SENSITIVITY:
        return "high"
    if tokens & _MEDIUM_SENSITIVITY or any(part in path.lower() for part in ("/users", "/accounts", "/patients", "/payments")):
        return "medium"
    return "low"


def build_inventory(records: list[dict]) -> list[dict]:
    """Aggregate sanitized capture records by (method, normalized path).

    Each item has: method, path, request_count, status_codes (sorted unique),
    last_status, last_seen (ISO timestamp string), query_params (safe names).
    Records are expected keys: method, path, status_code, created_at.
    """
    grouped: dict[tuple[str, str], dict] = {}
    for rec in records:
        method = str(rec.get("method", "")).upper()
        norm = normalize_path(str(rec.get("path", "/")))
        key = (method, norm)
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "method": method,
                "path": norm,
                "request_count": 0,
                "status_codes": set(),
                "last_status": rec.get("status_code", 0),
                "last_seen": rec.get("created_at", ""),
                "query_params": set(),
                "auth_types": set(),
                "sensitivity": "low",
            }
            grouped[key] = entry
        entry["request_count"] += 1
        entry["status_codes"].add(rec.get("status_code", 0))
        entry["last_status"] = rec.get("status_code", 0)
        # created_at is an ISO-ish 'YYYY-MM-DD HH:MM:SS' string; lexicographic
        # max works for "last seen".
        if str(rec.get("created_at", "")) >= str(entry["last_seen"]):
            entry["last_seen"] = rec.get("created_at", "")
        entry["query_params"].update(extract_query_param_names(str(rec.get("path", ""))))
        auth_type = str(rec.get("auth_type", "unknown"))
        entry["auth_types"].add(auth_type)
        sensitivity = classify_data_sensitivity(norm, entry["query_params"])
        if ["high", "medium", "low"].index(sensitivity) < ["high", "medium", "low"].index(entry["sensitivity"]):
            entry["sensitivity"] = sensitivity

    items = []
    for (method, norm), entry in sorted(grouped.items()):
        items.append(
            {
                "method": method,
                "path": norm,
                "request_count": entry["request_count"],
                "status_codes": sorted(entry["status_codes"]),
                "last_status": entry["last_status"],
                "last_seen": entry["last_seen"],
                "query_params": sorted(entry["query_params"]),
                "authentication_types": sorted(entry["auth_types"]),
                "data_sensitivity": entry["sensitivity"],
                "sensitivity_basis": sensitivity_basis(norm, entry["query_params"]),
                # Only ever 404/405: no endpoint was served, so it is not a confirmed live API.
                "confirmed_live": not (entry["status_codes"] and entry["status_codes"] <= UNRESOLVED_STATUSES),
            }
        )
    return items


def load_openapi_spec(spec_path: str | Path | None) -> dict:
    """Load a local OpenAPI JSON file and return documented operations.

    Returns ``{"ok": True, "operations": {(METHOD, /normalized/template)}}``
    or ``{"ok": False, "error": "<human-readable reason>"}``. Missing files,
    invalid JSON, oversized files and wrong shapes are handled gracefully and
    never raised. Error text never contains filesystem paths or file content.
    Only JSON specifications are supported (YAML is not).
    """
    if not spec_path:
        return {"ok": False, "error": "no OpenAPI specification configured"}
    path = Path(spec_path)
    try:
        if not path.is_file():
            return {"ok": False, "error": "OpenAPI specification not found"}
        if path.stat().st_size > MAX_SPEC_BYTES:
            return {"ok": False, "error": "invalid OpenAPI specification: file too large"}
        raw = path.read_text(encoding="utf-8")
        if path.suffix.lower() in {".yaml", ".yml"}:
            if yaml is None:
                return {"ok": False, "error": "YAML support unavailable; install PyYAML"}
            data = yaml.safe_load(raw)
        else:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                # Permit YAML content even when a file has a nonstandard extension.
                if yaml is None:
                    raise
                data = yaml.safe_load(raw)
    except _SPEC_PARSE_ERRORS:
        return {"ok": False, "error": "invalid OpenAPI specification: parse failed"}
    except OSError:
        return {"ok": False, "error": "OpenAPI specification could not be read"}
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return {"ok": False, "error": "invalid OpenAPI specification: missing 'paths' object"}

    operations: set[tuple[str, str]] = set()
    deprecated: set[tuple[str, str]] = set()
    security_schemes = data.get("components", {}).get("securitySchemes", {}) if isinstance(data.get("components", {}), dict) else {}
    for template, methods in data["paths"].items():
        if not isinstance(methods, dict):
            continue
        for http_method in methods:
            if http_method.lower() in {
                "get", "post", "put", "patch", "delete", "head", "options", "trace",
            }:
                operation = (http_method.upper(), normalize_spec_template(str(template)))
                operations.add(operation)
                details = methods.get(http_method, {})
                if isinstance(details, dict) and details.get("deprecated") is True:
                    deprecated.add(operation)
    return {"ok": True, "operations": operations, "deprecated": deprecated, "security_schemes": security_schemes}


def is_unresolved_route(entry: dict) -> bool:
    """True if every observed status for this inventory entry was 404/405."""
    statuses = set(entry.get("status_codes") or [])
    return bool(statuses) and statuses <= UNRESOLVED_STATUSES


def find_shadow_apis(
    inventory: list[dict], operations: set[tuple[str, str]]
) -> tuple[list[dict], list[dict]]:
    """Split inventory entries into (documented, undocumented) route lists.

    Each undocumented entry carries a ``reason`` string explaining why it was
    flagged as a shadow API.
    """
    documented: list[dict] = []
    undocumented: list[dict] = []
    for entry in inventory:
        key = (entry["method"].upper(), normalize_spec_template(entry["path"]))
        route = {"method": entry["method"], "path": entry["path"]}
        if key in operations:
            documented.append(route)
        elif not is_unresolved_route(entry):
            undocumented.append(
                {
                    **route,
                    "request_count": entry.get("request_count", 0),
                    "last_seen": entry.get("last_seen", ""),
                    "reason": (
                        "observed in captured traffic but not documented "
                        "in the OpenAPI specification"
                    ),
                }
            )
    return documented, undocumented
