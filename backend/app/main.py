"""FastAPI application factory."""

import json
import logging
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.routing import APIRoute

from app.auth import require_read
from app.capture import RequestCaptureMiddleware, sanitize_path
from app.config import (
    MIN_FP_SECRET_LENGTH,
    get_db_path,
    get_settings,
    resolve_fp_secret,
    validate_environment,
)
from app.gateway import load_gateway_config, parse_gateway_config
from app.gateway import router as gateway_router
from app.ownership import load_ownership, validate_ownership
from app.principals import load_principals, validate_principals
from app.ratelimit import RateLimitConfig, RateLimiter, enforce_rate_limit
from app.routes.alerts import router as alerts_router
from app.routes.demo_shop import router as demo_shop_router
from app.routes.health import router as health_router
from app.routes.findings import router as findings_router
from app.routes.inventory import router as inventory_router
from app.routes.policy import router as policy_router
from app.routes.shadow import router as shadow_router
from app.routes.source_scan import router as source_scan_router
from app.storage import init_db
from app.timeutil import utcnow


class RedactQueryFilter(logging.Filter):
    """Redact secret query values in uvicorn access-log lines."""

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple) and len(args) >= 3 and isinstance(args[2], str):
            record.args = (*args[:2], sanitize_path(args[2]), *args[3:])
        return True


def create_app(
    db_path: str | None = None,
    enable_capture: bool | None = None,
    fp_secret: str | None = None,
    enable_demo: bool | None = None,
    api_key: str | None = None,
    env: str | None = None,
    spec_dir: str | None = None,
    ownership: dict | None = None,
    clock: Callable[[], datetime] | None = None,
    rate_limits: dict | None = None,
    principals: dict | None = None,
    gateway: dict | None = None,
    rate_clock: Callable[[], float] | None = None,
) -> FastAPI:
    """Build the FastAPI app (factory keeps tests isolated and simple).

    ``clock`` returns naive-UTC "now" (injectable for deterministic tests).
    ``ownership`` is the confirmed-BOLA context (default: SENTINEL_OWNERSHIP_PATH).
    ``rate_limits`` / ``principals`` / ``gateway`` default to the files named by
    SENTINEL_RATE_LIMITS_PATH / SENTINEL_PRINCIPALS_PATH / SENTINEL_GATEWAY_CONFIG;
    ``rate_clock`` returns epoch seconds for the rate limiter (tests).
    """
    settings = get_settings()
    env = (env or settings.env).strip().lower()
    resolved_db = db_path or get_db_path()
    capture_enabled = settings.enable_capture if enable_capture is None else enable_capture
    if fp_secret is None and settings.fp_secret is not None:
        fp_secret = settings.fp_secret.get_secret_value()
    fp_key = resolve_fp_secret(fp_secret)
    if api_key is None and settings.api_key is not None:
        api_key = settings.api_key.get_secret_value()
    admin_key = resolve_fp_secret(api_key)
    if api_key and admin_key is None:
        # Fail loudly: a weak key must not silently leave the API open.
        raise ValueError(
            f"SENTINEL_API_KEY must be at least {MIN_FP_SECRET_LENGTH} characters"
        )
    demo_on = settings.enable_demo_target if enable_demo is None else enable_demo
    validate_environment(
        env,
        has_api_key=admin_key is not None,
        has_fp_secret=fp_key is not None,
        demo_enabled=bool(demo_on),
    )
    if admin_key is None:
        logging.getLogger(__name__).warning(
            "SENTINEL_API_KEY is not set: Sentinel read endpoints are open and "
            "write endpoints (scan, alert triage) are disabled."
        )
    if fp_secret and fp_key is None:
        # Never log the value itself.
        logging.getLogger(__name__).warning(
            "SENTINEL_FP_SECRET is shorter than %d characters; credential "
            "fingerprinting is disabled (client IP is used as actor).",
            MIN_FP_SECRET_LENGTH,
        )

    if rate_limits is None and settings.rate_limits_path:
        try:
            rate_limits = json.loads(Path(settings.rate_limits_path).read_text())
        except (OSError, ValueError) as err:
            raise ValueError(f"cannot read rate limits file: {type(err).__name__}") from None
    limiter = RateLimiter(RateLimitConfig.from_dict(rate_limits), rate_clock)
    if principals is not None:
        principal_map = validate_principals(principals)
    elif settings.principals_path:
        principal_map = load_principals(settings.principals_path)
    else:
        principal_map = {}
    if principal_map and fp_key is None:
        raise ValueError("principals need SENTINEL_FP_SECRET (>= 32 chars) to match credentials")
    # Say plainly who can get the VP quota; nothing is ever granted by default.
    vp_count = sum(p.role == "vp" for p in principal_map.values())
    if not principal_map:
        logging.getLogger(__name__).warning(
            "No principals configured (SENTINEL_PRINCIPALS_PATH unset): nobody can receive the "
            "VP quota; every caller gets the normal per-endpoint limits.")
    elif not vp_count:
        logging.getLogger(__name__).warning(
            "%d principals configured but none has role 'vp': nobody can receive the VP quota.",
            len(principal_map))
    else:
        logging.getLogger(__name__).info("%d principals configured, %d with the VP quota (21x).",
                                         len(principal_map), vp_count)
    if gateway is not None:
        gateway_cfg = parse_gateway_config(gateway)
    elif settings.gateway_config_path:
        gateway_cfg = load_gateway_config(settings.gateway_config_path)
    else:
        gateway_cfg = None
    if gateway_cfg is not None and gateway_cfg.needs_principals and not principal_map:
        raise ValueError("gateway routes with auth 'principal' need SENTINEL_PRINCIPALS_PATH")

    # Make sure the SQLite file/tables exist before serving traffic.
    if resolved_db != ":memory:":
        init_db(resolved_db)

    # Every routed endpoint is rate limited (gateway routes inside the gateway).
    app = FastAPI(title="API Sentinel", version=settings.version,
                  dependencies=[Depends(enforce_rate_limit)])
    # Shared handle so routes can reach this instance's SQLite file
    # (keeps tests isolated: each create_app() call gets its own database).
    app.state.db_path = resolved_db
    app.state.api_key = admin_key
    app.state.env = env
    app.state.clock = clock or utcnow
    app.state.spec_dirs = [d for d in (spec_dir, settings.spec_dir) if d]
    app.state.fp_key = fp_key
    app.state.rate_limiter = limiter
    app.state.principals = principal_map
    app.state.gateway = gateway_cfg
    if ownership is not None:
        app.state.ownership = validate_ownership(ownership)
    elif settings.ownership_path:
        app.state.ownership = load_ownership(settings.ownership_path)
    else:
        app.state.ownership = None
    access_log = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, RedactQueryFilter) for f in access_log.filters):
        access_log.addFilter(RedactQueryFilter())
    app.add_middleware(
        RequestCaptureMiddleware,
        enabled=capture_enabled,
        db_path=resolved_db,
        fp_secret=fp_key,
        strip_gateway_prefix=gateway_cfg is not None,
    )
    read_auth = [Depends(require_read)]
    app.include_router(health_router)  # open: liveness probes carry no key
    app.include_router(inventory_router, dependencies=read_auth)
    app.include_router(shadow_router, dependencies=read_auth)
    app.include_router(source_scan_router)
    app.include_router(findings_router, dependencies=read_auth)
    app.include_router(alerts_router)  # per-route read/write auth
    app.include_router(policy_router, dependencies=read_auth)
    if demo_on:
        app.include_router(demo_shop_router)
    if gateway_cfg is not None:
        app.include_router(gateway_router)
    routers = [health_router, inventory_router, shadow_router, source_scan_router, findings_router,
               alerts_router, policy_router] + ([demo_shop_router] if demo_on else [])
    own = {f"{'GET' if m == 'HEAD' else m} {r.path}" for router in routers
           for r in router.routes if isinstance(r, APIRoute) for m in r.methods}
    app.state.limited_endpoints = own | (gateway_cfg.endpoints if gateway_cfg else set())
    # A limit configured for an endpoint that does not exist is a typo: fail at startup.
    limiter.validate_endpoints(app.state.limited_endpoints)
    return app


def __getattr__(name: str):
    """Build ``app`` on first access so importing this module never touches a database.

    ``uvicorn app.main:app`` still works (it does getattr); tests and tools
    that only need ``create_app`` no longer create ``./api_sentinel.db``.
    """
    if name == "app":
        global _app
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)


_app: FastAPI | None = None
