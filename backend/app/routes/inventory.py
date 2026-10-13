"""API inventory route: aggregated observed endpoints."""

from fastapi import APIRouter, Request

from app.discovery import build_inventory
from app.schemas import InventoryResponse
from app.storage import fetch_captured_requests

router = APIRouter()


@router.get("/api/inventory", response_model=InventoryResponse)
def get_inventory(request: Request) -> InventoryResponse:
    """Aggregate captured requests by method + normalized path.

    Returns an empty item list (not an error) when nothing was captured yet.
    """
    db_path = request.app.state.db_path
    records = fetch_captured_requests(db_path)
    items = build_inventory(records)
    return InventoryResponse(
        items=items,
        total_requests=sum(item["request_count"] for item in items),
        total_endpoints=len(items),
    )
