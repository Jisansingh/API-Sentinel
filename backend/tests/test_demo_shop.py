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
