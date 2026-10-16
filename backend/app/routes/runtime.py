"""Runtime monitoring and behavioral baseline API."""
import sqlite3

from fastapi import APIRouter, Query, Request

from app.runtime_monitor import build_runtime_baselines, fetch_runtime_records
from app.storage import list_alerts
from app.traffic_history import evaluate

router = APIRouter()


@router.get("/api/runtime/baselines")
def get_runtime_baselines(request: Request, days: int = Query(30, ge=1, le=90)) -> dict:
    """Return safe telemetry summaries and peak-aware endpoint/caller baselines."""
    records = fetch_runtime_records(request.app.state.db_path)
    return build_runtime_baselines(records, now=request.app.state.clock(), days=days)


@router.get("/api/runtime/history")
def get_runtime_history(request: Request, days: int = Query(30, ge=1, le=90)) -> dict:
    """Persistent real-traffic history per endpoint with its adaptive baseline state (read-only)."""
    db = request.app.state.db_path
    with sqlite3.connect(str(db)) as conn:
        return evaluate(conn, list_alerts(db), now=request.app.state.clock(), days=days, persist=False)
