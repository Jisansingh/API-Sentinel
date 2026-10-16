"""Explainable per-endpoint risk scores and their recorded changes (read-only)."""

from fastapi import APIRouter, Request

from app.config import get_settings
from app.discovery import build_inventory, find_shadow_apis, load_openapi_spec
from app.endpoint_risk import explain_change, score_inventory, snapshot_view, unscored_inventory
from app.storage import fetch_captured_requests, latest_risk_snapshots, list_alerts, save_risk_snapshots

router = APIRouter()


def current_endpoint_risk(app, *, with_inventory: bool = False):
    """Score every observed endpoint from the stored traffic, alerts and configuration."""
    db_path = app.state.db_path
    records = fetch_captured_requests(db_path)
    inventory = build_inventory(records)
    spec = load_openapi_spec(get_settings().openapi_spec_path)
    documented = shadow = set()
    if spec["ok"]:
        doc, undoc = find_shadow_apis(inventory, spec["operations"])
        documented = {(r["method"], r["path"]) for r in doc}
        shadow = {(r["method"], r["path"]) for r in undoc}
    scored = score_inventory(inventory, records, list_alerts(db_path), documented=documented, shadow=shadow,
                             spec_loaded=spec["ok"], gateway_enabled=app.state.gateway is not None)
    return (scored, inventory) if with_inventory else scored


def snapshot_endpoint_risk(app) -> int:
    """Record genuine score changes (called after scans and alert triage, never on reads)."""
    results = current_endpoint_risk(app)
    return save_risk_snapshots(app.state.db_path,
                               [(r["method"], r["path"], snapshot_view(r)) for r in results],
                               app.state.clock().isoformat(timespec="seconds"))


@router.get("/api/risk/endpoints")
def get_endpoint_risk(request: Request) -> dict:
    """Every observed endpoint's score, factor contributions, evidence and latest change.

    ``change`` compares the current score with the latest stored snapshot when they
    differ, otherwise the latest snapshot with the one before it; it is null (with
    ``history`` explaining why) until a genuine earlier snapshot exists.
    """
    items, inventory = current_endpoint_risk(request.app, with_inventory=True)
    excluded = unscored_inventory(inventory)
    snaps = latest_risk_snapshots(request.app.state.db_path)
    for item in items:
        history = snaps.get((item["method"], item["path"]), [])
        view = snapshot_view(item)
        item["change"] = None
        if not history:
            item["history"] = "unavailable: no snapshot recorded yet (snapshots are taken by Run scan and alert triage)"
        elif history[0]["score"] != view["score"] or history[0]["factors"] != view["factors"]:
            item["change"] = explain_change(history[0], view, history[0]["created_at"], None)
            item["history"] = "current values differ from the latest snapshot; the next scan or triage records them"
        elif len(history) > 1:
            item["change"] = explain_change(history[1], history[0], history[1]["created_at"], history[0]["created_at"])
            item["history"] = "latest recorded change"
        else:
            item["history"] = f"one snapshot ({history[0]['created_at']}); no change recorded since"
    return {"items": items, "total": len(items), "excluded": excluded,
            "coverage": {"discovered": len(inventory), "scored": len(items), "not_scored": len(excluded)},
            "scale": "0-100; bands: 0 none, 1-39 low, 40-69 medium, 70-100 high",
            "not_scored": "Sentinel's own routes and routes that only ever answered 404/405 (no endpoint was served)",
            "factor_max_points": {f["factor"]: f["max_points"] for f in items[0]["factors"]} if items else {}}
