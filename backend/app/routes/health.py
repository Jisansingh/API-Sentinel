"""Health-check route."""

import sqlite3
from pathlib import Path

from fastapi import APIRouter, Request, Response

from app.config import get_settings
from app.schemas import HealthResponse

router = APIRouter()


def database_ok(db_path: str) -> bool:
    """True if the SQLite file opens read-write and has the tables (never creates it)."""
    if db_path == ":memory:":
        return True
    try:
        uri = Path(db_path).resolve().as_uri() + "?mode=rw"
        with sqlite3.connect(uri, uri=True, timeout=2) as conn:
            conn.execute("SELECT 1 FROM captured_requests LIMIT 1")
            conn.execute("SELECT 1 FROM alerts LIMIT 1")
        return True
    except (sqlite3.Error, OSError):
        return False


@router.get("/api/health", response_model=HealthResponse)
def get_health(request: Request, response: Response) -> HealthResponse:
    """Liveness + storage readiness. 503 when the database is not usable.

    Open (no key) and free of paths or secrets: only coarse status words.
    """
    settings = get_settings()
    ok = database_ok(request.app.state.db_path)
    if not ok:
        response.status_code = 503
    return HealthResponse(
        status="ok" if ok else "degraded",
        service=settings.app_name,
        version=settings.version,
        database="ok" if ok else "unavailable",
    )
