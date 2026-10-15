"""Read-only views of access control: effective rate limits and the audit trail."""

from fastapi import APIRouter, Query, Request

from app.ratelimit import VP_MULTIPLIER
from app.schemas import GatewayEventsResponse, RateLimitsResponse
from app.storage import list_gateway_events

router = APIRouter()


@router.get("/api/rate-limits", response_model=RateLimitsResponse)
def get_rate_limits(request: Request) -> RateLimitsResponse:
    """Every limited endpoint with its normal and VP (21x) quota per window."""
    limiter = request.app.state.rate_limiter
    overrides = limiter.config.overrides or {}
    items = [
        {"endpoint": e, "normal_limit": limiter.normal_limit(e),
         "vp_limit": limiter.limit_for(e, "vp"),
         "source": "configured" if e in overrides else "built-in default"
         if e in limiter.limits else "default_limit"}
        for e in sorted(request.app.state.limited_endpoints)
    ]
    return RateLimitsResponse(window_seconds=limiter.config.window_seconds,
                              vp_multiplier=VP_MULTIPLIER, items=items,
                              gateway_enabled=request.app.state.gateway is not None,
                              principals_configured=len(request.app.state.principals),
                              vp_principals=sum(p.role == "vp" for p in request.app.state.principals.values()))


@router.get("/api/gateway-events", response_model=GatewayEventsResponse)
def get_gateway_events(request: Request, limit: int = Query(default=200, ge=1, le=1000)) -> GatewayEventsResponse:
    """Recent rate-limit, firewall and privileged-access events (newest first)."""
    items = list_gateway_events(request.app.state.db_path, limit)
    return GatewayEventsResponse(items=items, total=len(items))
