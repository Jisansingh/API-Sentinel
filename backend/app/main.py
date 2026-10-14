"""FastAPI application factory."""

import logging

from fastapi import Depends, FastAPI

from app.auth import require_read
from app.capture import RequestCaptureMiddleware
from app.config import MIN_FP_SECRET_LENGTH, get_db_path, get_settings, resolve_fp_secret
from app.routes.alerts import router as alerts_router
from app.routes.demo_shop import router as demo_shop_router
from app.routes.health import router as health_router
from app.routes.findings import router as findings_router
from app.routes.inventory import router as inventory_router
from app.routes.shadow import router as shadow_router
from app.storage import init_db


def create_app(
    db_path: str | None = None,
    enable_capture: bool | None = None,
    fp_secret: str | None = None,
    enable_demo: bool | None = None,
    api_key: str | None = None,
) -> FastAPI:
    """Build the FastAPI app (factory keeps tests isolated and simple)."""
    settings = get_settings()
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

    # Make sure the SQLite file/tables exist before serving traffic.
    if resolved_db != ":memory:":
        init_db(resolved_db)

    app = FastAPI(title="API Sentinel", version=settings.version)
    # Shared handle so routes can reach this instance's SQLite file
    # (keeps tests isolated: each create_app() call gets its own database).
    app.state.db_path = resolved_db
    app.state.api_key = admin_key
    app.add_middleware(
        RequestCaptureMiddleware,
        enabled=capture_enabled,
        db_path=resolved_db,
        fp_secret=fp_key,
    )
    read_auth = [Depends(require_read)]
    app.include_router(health_router)  # open: liveness probes carry no key
    app.include_router(inventory_router, dependencies=read_auth)
    app.include_router(shadow_router, dependencies=read_auth)
    app.include_router(findings_router, dependencies=read_auth)
    app.include_router(alerts_router)  # per-route read/write auth
    if settings.enable_demo_target if enable_demo is None else enable_demo:
        app.include_router(demo_shop_router)
    return app


app = create_app()
