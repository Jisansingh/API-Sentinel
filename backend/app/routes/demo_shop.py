"""DELIBERATELY VULNERABLE demo target API ("shop") for Sentinel demos.

Never enable in production. Mounted only when ENABLE_DEMO_TARGET=true (or
create_app(enable_demo=True)). Its traffic is captured like any monitored API.
Intentional flaws, so Sentinel has something to detect:
- GET /shop/orders/{id} checks authentication but NOT ownership (BOLA).
- GET /shop/internal/export and GET /shop/admin/stats are missing from the
  published spec (shadow APIs).
- GET /shop/secure/orders/{id} is the fixed version (ownership enforced, 403), so a
  blocked cross-user attempt can be shown next to the vulnerable one.
Tokens are fixed demo strings, not secrets.
"""

from fastapi import APIRouter, Header, HTTPException

router = APIRouter(prefix="/shop")

DEMO_USERS = {"demo-alice-token": "alice", "demo-bob-token": "bob", "demo-mallory-token": "mallory"}
ORDERS = {i: {"id": i, "owner": "alice" if i % 2 else "bob", "total": 10 * i} for i in range(1, 11)}
PRODUCT_COUNT = 50


def _user(authorization: str | None) -> str:
    token = (authorization or "").removeprefix("Bearer ").strip()
    user = DEMO_USERS.get(token)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


@router.get("/products/{product_id}")
def get_product(product_id: int) -> dict:
    if not 1 <= product_id <= PRODUCT_COUNT:
        raise HTTPException(status_code=404, detail="product not found")
    return {"id": product_id, "name": f"Product {product_id}"}


@router.get("/me")
def get_me(authorization: str | None = Header(default=None)) -> dict:
    return {"user": _user(authorization)}


@router.get("/orders/{order_id}")
def get_order(order_id: int, authorization: str | None = Header(default=None)) -> dict:
    _user(authorization)  # authenticated...
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    return order  # ...but never checks order["owner"] == user: intentional BOLA


@router.get("/secure/orders/{order_id}")
def get_order_secure(order_id: int, authorization: str | None = Header(default=None)) -> dict:
    user = _user(authorization)
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    if order["owner"] != user:
        raise HTTPException(status_code=403, detail="not your order")
    return order


def demo_ownership(fingerprint) -> dict:
    """Ownership context for the synthetic demo data (confirmed/blocked BOLA rules).

    ``fingerprint(token)`` returns the stored credential fingerprint of a demo token,
    so the context never contains a raw token.
    """
    owners = {str(i): o["owner"] for i, o in ORDERS.items()}
    return {"resources": {"/shop/orders/{id}": owners, "/shop/secure/orders/{id}": dict(owners)},
            "actors": {fingerprint(token): user for token, user in DEMO_USERS.items()}}


@router.get("/internal/export")
def internal_export(authorization: str | None = Header(default=None)) -> dict:
    _user(authorization)
    return {"orders": len(ORDERS)}  # undocumented route: intentional shadow API


@router.get("/admin/stats")
def admin_stats(authorization: str | None = Header(default=None)) -> dict:
    _user(authorization)
    return {"users": len(DEMO_USERS)}  # second undocumented route: intentional shadow API
