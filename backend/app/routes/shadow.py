"""Shadow-API route: observed endpoints missing from the OpenAPI spec."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request

from app.config import get_settings
from app.discovery import (
    build_inventory,
    find_shadow_apis,
    is_unresolved_route,
    load_openapi_spec,
)
from app.schemas import ShadowApiResponse
from app.storage import fetch_captured_requests

router = APIRouter()


def resolve_spec_path(request: Request, requested: str | None, configured: str | None) -> str | None:
    """Pick the spec file to read, refusing arbitrary server-local paths.

    The operator-configured ``OPENAPI_SPEC_PATH`` is trusted. A caller-supplied
    ``spec_path`` must be a ``.json`` file inside an allowed directory: the
    configured spec's directory, ``SENTINEL_SPEC_DIR`` or the app's
    ``spec_dir``. Paths are resolved first, so ``..`` and symlinks cannot
    escape. Rejections say nothing about what exists on disk.
    """
    if not requested:
        return configured
    roots = [Path(d) for d in request.app.state.spec_dirs]
    if configured:
        roots.append(Path(configured).parent)
    try:
        target = Path(requested).resolve()
        allowed = target.suffix.lower() in {".json", ".yaml", ".yml"} and any(
            target.is_relative_to(root.resolve()) for root in roots
        )
    except (OSError, ValueError):
        allowed = False
    if not allowed:
        raise HTTPException(
            status_code=400,
            detail="spec_path must be a .json, .yaml, or .yml file inside an allowed specification directory",
        )
    return str(target)


@router.get("/api/shadow-apis", response_model=ShadowApiResponse)
def get_shadow_apis(
    request: Request,
    spec_path: str | None = Query(
        default=None,
        description=(
            "OpenAPI JSON/YAML file inside an allowed spec directory "
            "(overrides OPENAPI_SPEC_PATH; see SENTINEL_SPEC_DIR)."
        ),
    ),
) -> ShadowApiResponse:
    """Compare observed traffic against the documented OpenAPI operations.

    A missing or invalid specification is handled gracefully: the endpoint
    still returns 200 with ``spec_loaded=false``, an explanatory
    ``spec_error``, and every observed route listed as a shadow API with a
    reason that says documentation status is unknown.
    """
    settings = get_settings()
    resolved_spec = resolve_spec_path(request, spec_path, settings.openapi_spec_path)

    db_path = request.app.state.db_path
    inventory = build_inventory(fetch_captured_requests(db_path))

    spec = load_openapi_spec(resolved_spec)
    if not spec["ok"]:
        return ShadowApiResponse(
            documented=[],
            shadow_apis=[
                {
                    "method": entry["method"],
                    "path": entry["path"],
                    "request_count": entry["request_count"],
                    "last_seen": entry["last_seen"],
                    "reason": (
                        "observed in captured traffic; documentation status "
                        f"unknown ({spec['error']})"
                    ),
                }
                for entry in inventory
                if not is_unresolved_route(entry)
            ],
            deprecated_apis=[],
            unmanaged_apis=[],
            spec_loaded=False,
            spec_error=spec["error"],
        )

    documented, undocumented = find_shadow_apis(inventory, spec["operations"])
    deprecated_keys = spec.get("deprecated", set())
    deprecated = []
    for entry in inventory:
        key = (entry["method"].upper(), entry["path"])
        if key in deprecated_keys and not is_unresolved_route(entry):
            deprecated.append({"method": entry["method"], "path": entry["path"], "request_count": entry["request_count"], "last_seen": entry["last_seen"], "reason": "documented OpenAPI operation is marked deprecated"})
    # Undocumented endpoints are the unmanaged subset until an ownership registry is configured.
    return ShadowApiResponse(
        documented=documented,
        shadow_apis=undocumented,
        deprecated_apis=deprecated,
        unmanaged_apis=[{**item, "reason": "undocumented endpoint has no ownership/management record"} for item in undocumented],
        spec_loaded=True,
        spec_error=None,
    )
