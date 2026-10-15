"""FastAPI application factory."""

import logging
from collections.abc import Callable
from datetime import datetime

from fastapi import Depends, FastAPI

from app.auth import require_read
from app.capture import RequestCaptureMiddleware, sanitize_path
from app.config import (
    MIN_FP_SECRET_LENGTH,
    get_db_path,
    get_settings,
    resolve_fp_secret,
    validate_environment,
)
from app.ownership import load_ownership, validate_ownership
from app.routes.alerts import router as alerts_router
from app.routes.demo_shop import router as demo_shop_router
from app.routes.health import router as health_router
from app.routes.findings import router as findings_router
from app.routes.inventory import router as inventory_router
from app.routes.shadow import router as shadow_router
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
) -> FastAPI:
    """Build the FastAPI app (factory keeps tests isolated and simple).

    ``clock`` returns naive-UTC "now" (injectable for deterministic tests).
    ``ownership`` is the confirmed-BOLA context (default: SENTINEL_OWNERSHIP_PATH).
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

    # Make sure the SQLite file/tables exist before serving traffic.
    if resolved_db != ":memory:":
        init_db(resolved_db)

    app = FastAPI(title="API Sentinel", version=settings.version)
    # Shared handle so routes can reach this instance's SQLite file
    # (keeps tests isolated: each create_app() call gets its own database).
    app.state.db_path = resolved_db
    app.state.api_key = admin_key
    app.state.env = env
    app.state.clock = clock or utcnow
    app.state.spec_dirs = [d for d in (spec_dir, settings.spec_dir) if d]
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
    )
    read_auth = [Depends(require_read)]
    app.include_router(health_router)  # open: liveness probes carry no key
    app.include_router(inventory_router, dependencies=read_auth)
    app.include_router(shadow_router, dependencies=read_auth)
    app.include_router(findings_router, dependencies=read_auth)
    app.include_router(alerts_router)  # per-route read/write auth
    if demo_on:
        app.include_router(demo_shop_router)
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
