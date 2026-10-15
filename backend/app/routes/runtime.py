"""Runtime monitoring and behavioral baseline API."""
from fastapi import APIRouter, Query, Request

from app.runtime_monitor import build_runtime_baselines, fetch_runtime_records

router = APIRouter()


@router.get("/api/runtime/baselines")
def get_runtime_baselines(request: Request, days: int = Query(30, ge=1, le=90)) -> dict:
    """Return safe telemetry summaries and peak-aware endpoint/caller baselines."""
    records = fetch_runtime_records(request.app.state.db_path)
    return build_runtime_baselines(records, now=request.app.state.clock(), days=days)
