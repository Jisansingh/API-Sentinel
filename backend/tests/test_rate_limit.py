"""Phase 3: per-endpoint rate limits, server-side identity, VP quota = 21x."""

import logging
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient

from app.capture import credential_fingerprint
from app.main import create_app
from app.principals import validate_principals
from app.ratelimit import (
    DEFAULT_LIMITS,
    VP_MULTIPLIER,
    Identity,
    RateLimitConfig,
    RateLimiter,
    client_bucket,
)

FP = "f" * 40
ADMIN = "a" * 40
VP_TOKEN, USER_TOKEN = "Bearer vp-secret-token-123", "Bearer user-secret-token-456"


def fp(credential: str) -> str:
    return credential_fingerprint({"authorization": credential}, FP.encode())


PRINCIPALS = {"principals": [
    {"id": "jane-vp", "fingerprint": fp(VP_TOKEN), "role": "vp"},
    {"id": "bob", "fingerprint": fp(USER_TOKEN), "role": "user"},
]}


class Clock:
    def __init__(self, now: float = 1_000_000.0):
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def make(tmp_path):
    def build(limits=None, **kw):
        kw.setdefault("rate_clock", Clock())
        app = create_app(db_path=str(tmp_path / "rl.db"), fp_secret=FP, api_key=ADMIN,
                         principals=PRINCIPALS, rate_limits=limits, **kw)
        return app, TestClient(app)
    return build


def statuses(client, n, path="/api/health", **kw):
    return [client.get(path, **kw).status_code for _ in range(n)]


def events(app):
    with sqlite3.connect(app.state.db_path) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute("SELECT * FROM gateway_events")]


# --- limits per endpoint ----------------------------------------------------------------

def test_defaults_differ_per_endpoint_and_cover_every_route(make):
    app, _ = make(enable_demo=True)
    assert set(DEFAULT_LIMITS) == app.state.limited_endpoints  # no route left on a generic default
    assert len(set(DEFAULT_LIMITS.values())) > 3
    assert DEFAULT_LIMITS["POST /api/scan"] < DEFAULT_LIMITS["GET /api/health"]


def test_each_endpoint_enforces_its_own_limit(make):
    _, c = make({"limits": {"GET /api/health": 3, "GET /api/rate-limits": 5}})
    assert statuses(c, 4) == [200, 200, 200, 429]
    # a different endpoint has its own counter and limit
    assert statuses(c, 6, "/api/rate-limits", headers={"X-Sentinel-Key": ADMIN}) == [200] * 5 + [429]


def test_normal_user_below_at_and_above_limit(make):
    _, c = make({"limits": {"GET /api/health": 5}})
    seen = [c.get("/api/health", headers={"Authorization": USER_TOKEN}) for _ in range(6)]
    assert [r.status_code for r in seen] == [200] * 5 + [429]
    assert [r.headers["x-ratelimit-remaining"] for r in seen[:5]] == ["4", "3", "2", "1", "0"]
    assert seen[0].headers["x-ratelimit-limit"] == "5"


def test_429_has_retry_after_until_window_end(make):
    clock = Clock(1_000_000.5)  # window 60: 999_960 .. 1_000_020 -> 19.5 s left
    _, c = make({"limits": {"GET /api/health": 1}}, rate_clock=clock)
    c.get("/api/health")
    r = c.get("/api/health")
    assert r.status_code == 429 and r.json() == {"detail": "rate limit exceeded for this endpoint"}
    assert r.headers["retry-after"] == "20" and r.headers["x-ratelimit-remaining"] == "0"


def test_window_resets_and_is_configurable(make):
    clock = Clock(1_000_000.0)
    _, c = make({"window_seconds": 10, "limits": {"GET /api/health": 2}}, rate_clock=clock)
    assert statuses(c, 3) == [200, 200, 429]
    assert c.get("/api/health").headers["retry-after"] == "10"
    clock.now += 10  # next window
    assert statuses(c, 3) == [200, 200, 429]


# --- VP quota ---------------------------------------------------------------------------------

def test_vp_quota_is_21x_for_every_endpoint(make):
    app, c = make({"limits": {"GET /api/health": 7}}, enable_demo=True)
    limiter = app.state.rate_limiter
    assert VP_MULTIPLIER == 21
    for endpoint in app.state.limited_endpoints:
        assert limiter.limit_for(endpoint, "vp") == 21 * limiter.limit_for(endpoint, "user")
    body = c.get("/api/rate-limits", headers={"X-Sentinel-Key": ADMIN}).json()
    assert body["vp_multiplier"] == 21 and len(body["items"]) == len(app.state.limited_endpoints)
    assert all(i["vp_limit"] == 21 * i["normal_limit"] for i in body["items"])
    assert {"endpoint": "GET /api/health", "normal_limit": 7, "vp_limit": 147,
            "source": "configured"} in body["items"]


def test_normal_limit_50_gives_vp_exactly_1050_then_429(make):
    app, c = make({"limits": {"GET /api/health": 50}})
    vp = {"Authorization": VP_TOKEN}
    assert statuses(c, 50, headers={"Authorization": USER_TOKEN}) == [200] * 50
    assert c.get("/api/health", headers={"Authorization": USER_TOKEN}).status_code == 429
    codes = statuses(c, 1050, headers=vp)
    assert codes == [200] * 1050
    over = c.get("/api/health", headers=vp)
    assert over.status_code == 429 and over.headers["x-ratelimit-limit"] == "1050"
    rows = {(e["decision"], e["reason"], e["principal_id"]): e["count"] for e in events(app)}
    assert rows[("allowed", "vp_quota", "jane-vp")] == 1050
    assert rows[("rate_limited", "quota_exceeded", "jane-vp")] == 1


# --- identity cannot be forged ---------------------------------------------------------------

def test_role_headers_do_not_grant_vp_and_are_logged(make):
    app, c = make({"limits": {"GET /api/health": 2}})
    claim = {"X-Role": "vp", "X-User": "jane-vp", "X-Forwarded-User": "jane-vp"}
    assert statuses(c, 3, headers=claim) == [200, 200, 429]
    # a real non-VP principal claiming VP keeps its own normal quota
    assert statuses(c, 3, headers={**claim, "Authorization": USER_TOKEN}) == [200, 200, 429]
    reasons = {(e["reason"], e["identity_kind"]) for e in events(app)}
    assert ("unverified_privilege_claim", "ip") in reasons
    assert ("unverified_privilege_claim", "principal") in reasons
    assert not any(e["reason"] == "vp_quota" for e in events(app))


def test_rotating_unregistered_tokens_or_forwarded_for_share_one_bucket(make):
    _, c = make({"limits": {"GET /api/health": 3}})
    codes = [c.get("/api/health", headers={"Authorization": f"Bearer made-up-{i}",
                                           "X-Forwarded-For": f"203.0.113.{i}"}).status_code
             for i in range(5)]
    assert codes == [200, 200, 200, 429, 429]


def test_wrong_admin_keys_are_limited_before_auth(make):
    _, c = make({"limits": {"GET /api/inventory": 3}})
    codes = [c.get("/api/inventory", headers={"X-Sentinel-Key": f"guess-{i}" * 5}).status_code
             for i in range(5)]
    assert codes == [401, 401, 401, 429, 429]
    # the real admin has its own bucket and is authorized
    assert c.get("/api/inventory", headers={"X-Sentinel-Key": ADMIN}).status_code == 200


def test_ipv6_clients_are_grouped_by_64():
    assert client_bucket("2001:db8:1:2::1") == client_bucket("2001:db8:1:2:ffff::9")
    assert client_bucket("2001:db8:1:3::1") != client_bucket("2001:db8:1:2::1")
    assert client_bucket("::ffff:192.0.2.7") == client_bucket("192.0.2.7") == "ip:192.0.2.7"


# --- concurrency -------------------------------------------------------------------------------

def test_parallel_checks_never_exceed_the_quota():
    limiter = RateLimiter(RateLimitConfig(60, 50), Clock())
    who = Identity("ip", "ip:198.51.100.1")
    barrier = threading.Barrier(32)

    def burst(_):
        barrier.wait()
        return sum(limiter.check("GET /x", who).allowed for _ in range(20))

    with ThreadPoolExecutor(32) as pool:
        assert sum(pool.map(burst, range(32))) == 50


def test_parallel_http_requests_respect_the_limit(make):
    _, c = make({"limits": {"GET /api/health": 10}})
    with ThreadPoolExecutor(16) as pool:
        codes = list(pool.map(lambda _: c.get("/api/health").status_code, range(40)))
    assert codes.count(200) == 10 and codes.count(429) == 30


# --- configuration validation ----------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    {"window_seconds": 0}, {"window_seconds": True}, {"default_limit": 0},
    {"limits": {"GET /api/health": -1}}, {"limits": {"GET /api/health": 2.5}},
    {"limits": []}, {"unknown": 1}, [],
])
def test_bad_rate_limit_config_is_rejected(make, bad):
    with pytest.raises(ValueError):
        make(bad)


def test_limit_for_unknown_endpoint_is_a_startup_error(make):
    with pytest.raises(ValueError, match="unknown endpoints"):
        make({"limits": {"GET /api/helth": 5}})


@pytest.mark.parametrize("bad", [
    {"principals": [{"id": "x", "fingerprint": "abc", "role": "vp"}]},
    {"principals": [{"id": "x", "fingerprint": "0" * 32, "role": "admin"}]},
    {"principals": [{"id": "x", "fingerprint": "0" * 32, "role": "user", "purpose": "vip"}]},
    {"principals": [{"id": "x", "fingerprint": "0" * 32, "role": "vp"},
                    {"id": "x", "fingerprint": "1" * 32, "role": "user"}]},
    {"principals": [{"id": "x", "fingerprint": "0" * 32, "role": "vp", "token": "t"}]},
    {"users": []},
])
def test_bad_principals_are_rejected(bad):
    with pytest.raises(ValueError):
        validate_principals(bad)


def test_principals_need_a_fingerprint_secret(tmp_path):
    with pytest.raises(ValueError, match="SENTINEL_FP_SECRET"):
        create_app(db_path=str(tmp_path / "x.db"), fp_secret="", principals=PRINCIPALS)


def test_no_principals_means_no_vp(tmp_path):
    app = create_app(db_path=str(tmp_path / "x.db"), fp_secret=FP,
                     rate_limits={"limits": {"GET /api/health": 1}})
    c = TestClient(app)
    assert statuses(c, 2, headers={"Authorization": VP_TOKEN}) == [200, 429]


# --- audit trail never holds credentials ------------------------------------------------------

def test_events_and_logs_hold_no_credentials(make, caplog):
    app, c = make({"limits": {"GET /api/health": 1}})
    caplog.set_level(logging.INFO, logger="api_sentinel.ratelimit")
    for h in ({"Authorization": VP_TOKEN}, {"Authorization": USER_TOKEN, "X-Role": "vp"},
              {"X-Sentinel-Key": ADMIN}):
        statuses(c, 2, "/api/health?token=query-secret-789", headers=h)
    with open(app.state.db_path, "rb") as f:
        raw = f.read()
    for secret in ("vp-secret-token-123", "user-secret-token-456", "query-secret-789", ADMIN):
        assert secret.encode() not in raw
        assert secret not in caplog.text
    assert "principal=jane-vp" in caplog.text



@pytest.mark.parametrize("normal", [1, 2, 7, 50])
def test_vp_quota_is_multiplied_not_added(make, normal):
    app, c = make({"limits": {"GET /api/health": normal}})
    limiter = app.state.rate_limiter
    assert limiter.limit_for("GET /api/health", "vp") == normal * 21 != normal + 21
    vp = {"Authorization": VP_TOKEN}
    assert statuses(c, normal * 21 + 1, headers=vp) == [200] * (normal * 21) + [429]


def test_vp_configuration_is_reported(tmp_path, caplog):
    caplog.set_level(logging.INFO, logger="app.main")
    app = create_app(db_path=str(tmp_path / "a.db"), fp_secret=FP)
    assert "nobody can receive the VP quota" in caplog.text
    body = TestClient(app).get("/api/rate-limits").json()
    assert body["principals_configured"] == 0 and body["vp_principals"] == 0
    caplog.clear()
    only_user = {"principals": [PRINCIPALS["principals"][1]]}
    create_app(db_path=str(tmp_path / "b.db"), fp_secret=FP, principals=only_user)
    assert "none has role 'vp'" in caplog.text
    caplog.clear()
    app = create_app(db_path=str(tmp_path / "c.db"), fp_secret=FP, principals=PRINCIPALS)
    assert "1 with the VP quota" in caplog.text
    assert TestClient(app).get("/api/rate-limits").json()["vp_principals"] == 1


def test_production_still_fails_closed_with_phase34_options(tmp_path):
    with pytest.raises(ValueError, match="insecure production"):
        create_app(db_path=str(tmp_path / "p.db"), env="production", principals=PRINCIPALS, fp_secret=FP)
    with pytest.raises(ValueError, match="SENTINEL_FP_SECRET"):
        create_app(db_path=str(tmp_path / "q.db"), env="production", api_key=ADMIN, principals=PRINCIPALS)
