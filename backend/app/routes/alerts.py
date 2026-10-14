"""Persistent alerts: explicit scans write them; GET only reads."""

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from app.auth import require_read, require_write
from app.analysis import alert_actor, analyze_captured_traffic
from app.schemas import Alert, AlertsResponse, AlertStatus, AlertUpdate, ScanResponse
from app.storage import fetch_captured_requests, list_alerts, update_alert_status, upsert_alerts

router = APIRouter()


@router.post("/api/scan", response_model=ScanResponse, dependencies=[Depends(require_write)])
def run_scan(request: Request) -> ScanResponse:
    """Analyze captured traffic and upsert deduplicated alerts.

    The only endpoint that writes alerts; re-scanning unchanged traffic is
    a no-op (``unchanged``), so it is safe to call repeatedly.
    """
    db_path = request.app.state.db_path
    # all windows: a burst that ended before this scan must still be recorded
    findings = analyze_captured_traffic(
        fetch_captured_requests(db_path), scraping_all_windows=True
    )
    counts = upsert_alerts(db_path, [{**f, "actor": alert_actor(f)} for f in findings])
    return ScanResponse(findings=len(findings), **counts)


@router.get("/api/alerts", response_model=AlertsResponse, dependencies=[Depends(require_read)])
def get_alerts(request: Request, status: AlertStatus | None = Query(default=None)) -> AlertsResponse:
    """List stored alerts (newest activity first). Never triggers a scan."""
    items = list_alerts(request.app.state.db_path, status)
    return AlertsResponse(items=items, total=len(items))


@router.patch("/api/alerts/{alert_id}", response_model=Alert, dependencies=[Depends(require_write)])
def patch_alert(alert_id: int, update: AlertUpdate, request: Request) -> Alert:
    """Change an alert's triage status (open/acknowledged/resolved/ignored)."""
    alert = update_alert_status(request.app.state.db_path, alert_id, update.status, update.note)
    if alert is None:
        raise HTTPException(status_code=404, detail="alert not found")
    return Alert(**alert)
