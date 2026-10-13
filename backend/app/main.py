"""FastAPI application factory."""

from fastapi import FastAPI

from app.capture import RequestCaptureMiddleware
from app.config import get_db_path, get_settings
from app.routes.health import router as health_router
from app.routes.findings import router as findings_router
from app.routes.inventory import router as inventory_router
from app.routes.shadow import router as shadow_router
from app.storage import init_db


def create_app(db_path: str | None = None, enable_capture: bool | None = None) -> FastAPI:
    """Build the FastAPI app (factory keeps tests isolated and simple)."""
    settings = get_settings()
    resolved_db = db_path or get_db_path()
    capture_enabled = settings.enable_capture if enable_capture is None else enable_capture

    # Make sure the SQLite file/tables exist before serving traffic.
    if resolved_db != ":memory:":
        init_db(resolved_db)

    app = FastAPI(title="API Sentinel", version=settings.version)
    # Shared handle so routes can reach this instance's SQLite file
    # (keeps tests isolated: each create_app() call gets its own database).
    app.state.db_path = resolved_db
    app.add_middleware(
        RequestCaptureMiddleware, enabled=capture_enabled, db_path=resolved_db
    )
    app.include_router(health_router)
    app.include_router(inventory_router)
    app.include_router(shadow_router)
    app.include_router(findings_router)
    return app


app = create_app()
