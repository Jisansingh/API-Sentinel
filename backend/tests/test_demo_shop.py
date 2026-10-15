"""P5: deliberately vulnerable demo target + attack simulator, end to end."""

from fastapi.testclient import TestClient

from app.main import create_app
from simulator.run import SHOP_SPEC, TOKENS, run_scenarios

FP_SECRET = "d" * 32
API_KEY = "a" * 32


def _app(tmp_path, **kw):
    return create_app(
        db_path=str(tmp_path / "demo.db"), fp_secret=FP_SECRET, api_key=API_KEY,
        spec_dir=str(SHOP_SPEC.parent), **kw,
    )


def test_demo_target_is_off_by_default(tmp_path):
    client = TestClient(_app(tmp_path))
    assert client.get("/shop/products/1").status_code == 404


def test_demo_target_behaviour_including_intentional_bola(tmp_path):
    client = TestClient(_app(tmp_path, enable_demo=True))
    auth = lambda who: {"Authorization": f"Bearer {TOKENS[who]}"}  # noqa: E731
    assert client.get("/shop/orders/1").status_code == 401
    assert client.get("/shop/me", headers=auth("alice")).json()["user"] == "alice"
    assert client.get("/shop/orders/999", headers=auth("alice")).status_code == 404
    # Order 1 belongs to alice; the demo API deliberately skips the owner check.
    assert client.get("/shop/orders/1", headers=auth("mallory")).status_code == 200


def test_simulator_scenarios_raise_expected_alerts(tmp_path):
    app = _app(tmp_path, enable_demo=True)

    def send(method, path, headers, ip):
        return TestClient(app, client=(ip, 5000)).request(method, path, headers=headers).status_code

    run_scenarios(send)
    client = TestClient(app, headers={"X-Sentinel-Key": API_KEY})
    assert client.post("/api/scan").status_code == 200
    alerts = client.get("/api/alerts").json()["items"]
    by_type = {}
    for a in alerts:
        by_type.setdefault(a["detection_type"], []).append(a)

    assert {"scraping", "bola_enumeration", "token_replay"} <= set(by_type)
    assert [a["endpoint"] for a in by_type["bola_enumeration"]] == ["/shop/orders/{id}"]
    assert len(by_type["token_replay"]) == 1
    # Normal user traffic raises nothing for alice's IP.
    assert not [a for a in alerts if a["metadata"].get("client_ip") == "10.0.0.2"]

    shadow = client.get("/api/shadow-apis", params={"spec_path": str(SHOP_SPEC)}).json()
    assert {s["path"] for s in shadow["shadow_apis"]} == {
        "/shop/internal/export", "/shop/admin/stats",
    }

    with __import__("sqlite3").connect(str(tmp_path / "demo.db")) as conn:
        dump = "\n".join(conn.iterdump())
    assert not any(token in dump for token in TOKENS.values())


def test_ownership_context_turns_the_intentional_bola_into_a_confirmed_alert(tmp_path):
    """Live path: demo shop -> capture -> fingerprint -> ownership context -> scan."""
    from simulator.ownership import build_context

    app = _app(tmp_path, enable_demo=True, ownership=build_context(FP_SECRET.encode()))
    client = TestClient(app)
    as_alice, as_mallory = {"Authorization": "Bearer demo-alice-token"}, {"Authorization": "Bearer demo-mallory-token"}
    assert client.get("/shop/orders/1", headers=as_alice).status_code == 200   # her own order
    assert client.get("/shop/orders/3", headers=as_alice).status_code == 200
    assert client.get("/shop/orders/2", headers=as_mallory).status_code == 200  # bob's order
    admin = TestClient(app, headers={"X-Sentinel-Key": API_KEY})
    admin.post("/api/scan")
    alerts = admin.get("/api/alerts").json()["items"]
    assert [(a["detection_type"], a["metadata"]["user_id"]) for a in alerts] == [("bola", "mallory")]
    assert "demo-mallory-token" not in str(alerts)


SHOP_ROUTES = {"/shop/products/{product_id}", "/shop/me", "/shop/orders/{order_id}",
               "/shop/internal/export", "/shop/admin/stats"}


def test_demo_routes_are_registered_only_when_enabled(tmp_path):
    off = _app(tmp_path / "off", enable_demo=False)
    on = _app(tmp_path / "on", enable_demo=True)
    assert not {p for p in off.openapi()["paths"] if p.startswith("/shop/")}
    assert SHOP_ROUTES <= set(on.openapi()["paths"])
    for path in ("/shop/products/1", "/shop/me", "/shop/orders/1", "/shop/internal/export", "/shop/admin/stats"):
        assert TestClient(off).get(path).status_code == 404


def test_dashboard_sample_traffic_succeeds_and_feeds_detection_when_enabled(tmp_path):
    """The exact plan behind 'Generate sample traffic' (demo/index.html), then a scan."""
    import json
    import re
    import sqlite3
    from pathlib import Path

    html = (Path(__file__).resolve().parents[2] / "demo" / "index.html").read_text()
    plan = json.loads(re.search(r'<script type="application/json" id="sample-traffic">(.*?)</script>', html, re.S).group(1))
    app = _app(tmp_path, enable_demo=True)
    client = TestClient(app)
    codes = [client.get(s["path"], headers={"Authorization": f"Bearer {s['token']}"} if s["token"] else {}).status_code
             for s in plan]
    assert codes == [200] * len(plan)
    with sqlite3.connect(app.state.db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM captured_requests WHERE path LIKE '/shop/%'").fetchone()[0] == len(plan)
    scan = client.post("/api/scan", headers={"X-Sentinel-Key": API_KEY}, json={}).json()
    assert scan["findings"] >= 1 and scan["created"] >= 1
    alerts = client.get("/api/alerts", headers={"X-Sentinel-Key": API_KEY}).json()["items"]
    assert any(a["detection_type"] == "scraping" for a in alerts)
