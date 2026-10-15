"""Traffic simulator for the demo shop: normal use plus four attack patterns.

Run the backend with the demo target and a fingerprint key, then this:

    export SENTINEL_FP_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    export SENTINEL_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
    ENABLE_DEMO_TARGET=true uvicorn app.main:app --port 8000      # from backend/
    python3 -m simulator.run                                       # from backend/
    curl -X POST -H "X-Sentinel-Key: $SENTINEL_API_KEY" http://127.0.0.1:8000/api/scan

Distinct client IPs are simulated with X-Forwarded-For, which uvicorn
trusts from 127.0.0.1 by default (--forwarded-allow-ips). Standard library only.
"""

import os
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path

from app.routes.demo_shop import DEMO_USERS

TOKENS = {user: token for token, user in DEMO_USERS.items()}
SHOP_SPEC = Path(__file__).resolve().parent / "shop-openapi.json"

Send = Callable[[str, str, dict, str], int]


def _auth(user: str) -> dict:
    return {"Authorization": f"Bearer {TOKENS[user]}"}


def run_scenarios(send: Send) -> None:
    """Drive every scenario through ``send(method, path, headers, ip)``."""
    # Normal: alice browses a little and reads her own order.
    for path in ("/shop/me", "/shop/products/1", "/shop/products/2", "/shop/orders/1"):
        send("GET", path, _auth("alice"), "10.0.0.2")
    # Shadow APIs: two undocumented routes that answer.
    send("GET", "/shop/internal/export", _auth("alice"), "10.0.0.2")
    send("GET", "/shop/admin/stats", _auth("alice"), "10.0.0.2")
    # Scraping: anonymous bulk read of the catalogue.
    for i in range(1, 41):
        send("GET", f"/shop/products/{i}", {}, "10.0.0.66")
    # BOLA enumeration: mallory walks order IDs; most do not exist (404).
    for i in range(1, 31):
        send("GET", f"/shop/orders/{i}", _auth("mallory"), "10.0.0.77")
    # Token replay: bob's token used from five different IPs.
    for n in range(1, 6):
        send("GET", "/shop/me", _auth("bob"), f"10.0.1.{n}")


def http_sender(base_url: str) -> Send:
    def send(method: str, path: str, headers: dict, ip: str) -> int:
        req = urllib.request.Request(
            base_url + path, method=method, headers={**headers, "X-Forwarded-For": ip}
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status
        except urllib.error.HTTPError as err:  # 401/404 are expected traffic
            return err.code

    return send


if __name__ == "__main__":
    base = os.getenv("SENTINEL_URL", "http://127.0.0.1:8000").rstrip("/")
    run_scenarios(http_sender(base))
    print(f'Traffic sent to {base}. Next: curl -X POST -H "X-Sentinel-Key: $SENTINEL_API_KEY" {base}/api/scan')
