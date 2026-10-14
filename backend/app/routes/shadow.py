"""Shadow-API route: observed endpoints missing from the OpenAPI spec."""

from fastapi import APIRouter, Query, Request

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


@router.get("/api/shadow-apis", response_model=ShadowApiResponse)
def get_shadow_apis(
    request: Request,
    spec_path: str | None = Query(
        default=None,
        description="Local OpenAPI JSON file path (overrides OPENAPI_SPEC_PATH).",
    ),
) -> ShadowApiResponse:
    """Compare observed traffic against the documented OpenAPI operations.

    A missing or invalid specification is handled gracefully: the endpoint
    still returns 200 with ``spec_loaded=false``, an explanatory
    ``spec_error``, and every observed route listed as a shadow API with a
    reason that says documentation status is unknown.
    """
    settings = get_settings()
    resolved_spec = spec_path or settings.openapi_spec_path

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
            spec_loaded=False,
            spec_error=spec["error"],
        )

    documented, undocumented = find_shadow_apis(inventory, spec["operations"])
    return ShadowApiResponse(
        documented=documented,
        shadow_apis=undocumented,
        spec_loaded=True,
        spec_error=None,
    )
