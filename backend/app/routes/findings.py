"""Findings route: structured abuse-detection results from captured traffic."""

from fastapi import APIRouter, Query, Request

from app.analysis import (
    DEFAULT_DISTINCT_THRESHOLD,
    DEFAULT_RATE_THRESHOLD,
    DEFAULT_TIME_WINDOW_SECONDS,
    analyze_captured_traffic,
)
from app.schemas import FindingsResponse
from app.storage import fetch_captured_requests

router = APIRouter()


@router.get("/api/findings", response_model=FindingsResponse)
def get_findings(
    request: Request,
    time_window_seconds: int = Query(default=DEFAULT_TIME_WINDOW_SECONDS, ge=1),
    rate_threshold: int = Query(default=DEFAULT_RATE_THRESHOLD, ge=1),
    distinct_threshold: int = Query(default=DEFAULT_DISTINCT_THRESHOLD, ge=1),
) -> FindingsResponse:
    """Analyze captured traffic and return deterministic risk-scored findings.

    Currently surfaces scraping findings derived from capture data grouped
    by client IP. BOLA and token-replay require explicit authorization
    context / token inputs (never inferred from traffic, never stored), so
    they produce no findings here by default — see ``app.analysis``. Empty
    databases return HTTP 200 with an empty item list.
    """
    db_path = request.app.state.db_path
    try:
        records = fetch_captured_requests(db_path)
    except Exception:
        records = []
    items = analyze_captured_traffic(
        records,
        time_window_seconds=time_window_seconds,
        rate_threshold=rate_threshold,
        distinct_threshold=distinct_threshold,
    )
    return FindingsResponse(items=items, total_findings=len(items))
