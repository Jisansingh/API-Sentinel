"""API discovery: path normalization, inventory building, OpenAPI comparison.

Beginner-friendly pure functions (no FastAPI/SQLite imports here), so they
are easy to unit-test. Privacy rule: we aggregate already-sanitized capture
records — method, path, status, timing. We use query-parameter NAMES only,
never values, and never touch bodies, tokens, or passwords.
"""

import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

# A segment that is only digits: /users/101, /orders/2024, ...
_NUMERIC_SEGMENT = re.compile(r"^\d+$")

# UUID-like segments: 8-4-4-4-12 hex (with dashes) or 32 hex chars.
_UUID_SEGMENT = re.compile(
    r"^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32})$"
)

# A route that only ever answered with these never resolved to a real
# operation (scanner probes, typos). Same default idea as Wallarm
# api-firewall's shadow-API exclude list (404).
UNRESOLVED_STATUSES = frozenset({404, 405})

# OpenAPI path-template placeholder: /users/{id}, /users/{userId}, ...
_SPEC_PLACEHOLDER = re.compile(r"\{[^}/]+\}")


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


def normalize_path(path: str) -> str:
    """Normalize an observed request path into an inventory key.

    - Drops the query string (parameter names are tracked separately).
    - Maps numeric / UUID-like segments to ``{id}``.
    - Keeps every other segment exactly as observed.
    - Strips one trailing slash (``/users/`` -> ``/users``).

    Examples:
        ``/users/101`` -> ``/users/{id}``
        ``/users/search`` -> ``/users/search`` (unchanged)
    """
    raw = _strip_trailing_slash(urlsplit(path).path or "/")
    if raw == "/":
        return "/"
    parts = [
        "{id}" if _is_resource_id(seg) else seg for seg in raw.split("/") if seg != ""
    ]
    return "/" + "/".join(parts)


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
            }
        )
    return items


def load_openapi_spec(spec_path: str | Path | None) -> dict:
    """Load a local OpenAPI JSON file and return documented operations.

    Returns ``{"ok": True, "operations": {(METHOD, /normalized/template)}}``
    or ``{"ok": False, "error": "<human-readable reason>"}``. Missing files,
    invalid JSON, and wrong shapes are handled gracefully — never raised.
    Only JSON specifications are supported in this step.
    """
    if not spec_path:
        return {"ok": False, "error": "no OpenAPI specification configured"}
    path = Path(spec_path)
    if not path.is_file():
        return {"ok": False, "error": f"OpenAPI specification not found: {path}"}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError, UnicodeDecodeError) as exc:
        return {"ok": False, "error": f"invalid OpenAPI specification: {exc}"}
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return {"ok": False, "error": "invalid OpenAPI specification: missing 'paths' object"}

    operations: set[tuple[str, str]] = set()
    for template, methods in data["paths"].items():
        if not isinstance(methods, dict):
            continue
        for http_method in methods:
            if http_method.lower() in {
                "get", "post", "put", "patch", "delete", "head", "options", "trace",
            }:
                operations.add(
                    (http_method.upper(), normalize_spec_template(str(template)))
                )
    return {"ok": True, "operations": operations}


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
