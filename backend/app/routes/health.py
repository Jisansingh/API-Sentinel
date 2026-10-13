"""Health-check route."""

from fastapi import APIRouter

from app.config import get_settings
from app.schemas import HealthResponse

router = APIRouter()


@router.get("/api/health", response_model=HealthResponse)
def get_health() -> HealthResponse:
    """Return a simple liveness payload used by tests and monitoring."""
    settings = get_settings()
    return HealthResponse(status="ok", service=settings.app_name, version=settings.version)
