"""Ownership context for the demo shop (enables confirmed-BOLA detection).

The shop's tokens are public demo fixtures; Sentinel only ever stores keyed
fingerprints of them, so the file written here holds fingerprints and owners,
never tokens. Run from ``backend/`` with the SAME SENTINEL_FP_SECRET as the
backend, then point the backend at the file:

    python3 -m simulator.ownership > /path/to/ownership.json
    SENTINEL_OWNERSHIP_PATH=/path/to/ownership.json ENABLE_DEMO_TARGET=true uvicorn app.main:app
"""

import json
import os
import sys

from app.capture import credential_fingerprint
from app.config import resolve_fp_secret
from app.routes.demo_shop import DEMO_USERS, ORDERS


def build_context(secret: bytes) -> dict:
    """Ownership context keyed by the fingerprints Sentinel stores for demo users."""
    actors = {
        credential_fingerprint({"authorization": f"Bearer {token}"}, secret): user
        for token, user in DEMO_USERS.items()
    }
    owners = {str(order["id"]): order["owner"] for order in ORDERS.values()}
    return {"resources": {"/shop/orders/{id}": owners}, "actors": actors}


if __name__ == "__main__":
    secret = resolve_fp_secret(os.getenv("SENTINEL_FP_SECRET"))
    if secret is None:
        sys.exit("SENTINEL_FP_SECRET (>= 32 chars) must be set to the backend's value")
    print(json.dumps(build_context(secret), indent=2, sort_keys=True))
