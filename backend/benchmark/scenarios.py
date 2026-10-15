"""Labelled, deterministic traffic scenarios for the demo shop API.

SYNTHETIC data: records are generated from fixed timestamps and a seeded RNG,
modelled on the demo shop (``app/routes/demo_shop.py``). Results measure how
well the detectors separate *these* scenarios; they are not real-world rates.

Ground truth (per scenario):
- ``expected``: detection types that MUST fire for every instance.
- ``tolerated``: types that may fire without counting as FP or FN (e.g. a
  30-request ID walk is legitimately also a high-rate burst).
Every other detection type must stay silent for that instance.
"""

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

DETECTION_TYPES = ("scraping", "bola_enumeration", "bola", "token_replay")
T0 = datetime(2026, 1, 5, 9, 0, 0)  # fixed epoch: runs are reproducible
INSTANCES = 5

# Benchmark-only constants (not secrets; never reused outside the benchmark).
BENCH_FP_SECRET = "benchmark-only-fingerprint-key-0123456789abcdef"
BENCH_API_KEY = "benchmark-only-admin-key-0123456789abcdefghij"

ORDER_OWNERS = {str(i): ("alice" if i % 2 else "bob") for i in range(1, 11)}
PRODUCT_COUNT = 50

# Published spec of the benchmark shop: two routes are intentionally missing.
SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "bench shop", "version": "1"},
    "paths": {
        "/shop/me": {"get": {}},
        "/shop/products/{product_id}": {"get": {}},
        "/shop/orders/{order_id}": {"get": {}},
    },
}
# (method, normalized template) of routes that really are undocumented.
UNDOCUMENTED_TRUTH = {("GET", "/shop/internal/export"), ("GET", "/shop/admin/stats")}
# Observed routes that are NOT shadow APIs (404 probes, Sentinel's own routes).
NOT_SHADOW_TRUTH = {
    ("GET", "/.env"), ("GET", "/wp-login.php"), ("GET", "/docs"), ("GET", "/openapi.json"),
}


@dataclass
class Instance:
    scenario: str
    index: int
    ips: set = field(default_factory=set)
    tokens: set = field(default_factory=set)
    user: str | None = None


@dataclass
class Scenario:
    name: str
    description: str
    expected: frozenset
    tolerated: frozenset = frozenset()
    # Holdout scenarios were written AFTER the Phase 2 detector changes and
    # never used for tuning; they include cases the detectors are known to miss.
    holdout: bool = False


SCENARIOS = [
    Scenario("normal_browse", "user browses a little and reads their own order", frozenset()),
    Scenario("scraping_bulk", "anonymous bulk read of 40 products in 30 s", frozenset({"scraping"})),
    Scenario("scraping_low_slow", "anonymous harvest: 150 requests over 50 products at 1 req/12 s",
             frozenset({"scraping"})),
    # The walk also successfully reads orders 2-10 owned by others, so confirmed
    # BOLA is ground truth here too (label corrected after review, see report).
    Scenario("bola_enumeration", "user walks 30 order IDs, mostly 404",
             frozenset({"bola_enumeration", "bola"}), frozenset({"scraping"})),
    Scenario("bola_unauthorized_read", "user reads 4 orders owned by others, all 200",
             frozenset({"bola"})),
    Scenario("token_replay", "one token used from 5 IPs within 20 s", frozenset({"token_replay"})),
    Scenario("legit_high_volume", "authenticated client polls two own endpoints, 40 req/min",
             frozenset()),
    Scenario("repeated_small_set", "anonymous widget refreshes 3 products every 3 s for 3 min",
             frozenset()),
    Scenario("roaming_user", "legit user's token seen from 4 IPs, 10 min apart", frozenset()),
    Scenario("probe_404_scanner", "scanner hits unknown paths once each (all 404)", frozenset()),
    Scenario("typo_denied_user", "user requests 5 order IDs, 4 denied (403)", frozenset()),
    # ---- holdout set (not tuned on) ----
    Scenario("h_scrape_sequential_walk", "anonymous walks products 1-50 at 1 req/2 s",
             frozenset({"scraping"}), holdout=True),
    Scenario("h_bola_slow_probe", "user probes 12 unknown order IDs over 20 min (404)",
             frozenset({"bola_enumeration"}), holdout=True),
    Scenario("h_replay_slow_distributed", "stolen token used from 5 IPs, one request every 30 min",
             frozenset({"token_replay"}), holdout=True),
    Scenario("h_nat_office", "6 users behind one IP, each browsing a few products",
             frozenset(), holdout=True),
    Scenario("h_partner_sync", "authorised partner reads the whole catalogue (50 products) in 40 s",
             frozenset(), holdout=True),
    Scenario("h_two_devices", "one user's token alternates between phone and laptop IPs",
             frozenset(), holdout=True),
    Scenario("h_owner_reads_own", "user reads their own five orders",
             frozenset(), holdout=True),
]


def _rec(out, t, ip, token, path, status, method="GET"):
    out.append({"t": t, "ip": ip, "token": token, "method": method, "path": path, "status": status})


def _product_status(i):
    return 200 if 1 <= i <= PRODUCT_COUNT else 404


def _order_status(i, authorised=True):
    return 200 if str(i) in ORDER_OWNERS else 404


def build(seed: int = 20260105):
    """Return (records, instances). Records: dicts with datetime ``t``."""
    rng = random.Random(seed)
    records: list[dict] = []
    instances: list[Instance] = []
    for s_idx, sc in enumerate(SCENARIOS):
        for i in range(INSTANCES):
            ip = f"10.{s_idx + 1}.{i + 1}.10"
            tok = f"bench-{sc.name}-{i}"
            inst = Instance(sc.name, i, ips={ip}, tokens={tok} if sc.name not in (
                "scraping_bulk", "scraping_low_slow", "repeated_small_set", "probe_404_scanner",
                "h_scrape_sequential_walk",
            ) else set())
            # 4h per scenario, 40 min per instance: windows never overlap.
            t = T0 + timedelta(hours=4 * s_idx, minutes=40 * i + rng.randint(0, 5))
            auth = tok if inst.tokens else None
            n = sc.name
            if n == "normal_browse":
                inst.user = "alice"
                _rec(records, t, ip, tok, "/shop/me", 200)
                for k in range(3):
                    _rec(records, t + timedelta(seconds=40 * (k + 1)), ip, tok,
                         f"/shop/products/{rng.randint(1, 50)}", 200)
                _rec(records, t + timedelta(seconds=200), ip, tok, "/shop/orders/1", 200)
            elif n == "scraping_bulk":
                for k in range(40):
                    _rec(records, t + timedelta(seconds=k * 0.75), ip, None,
                         f"/shop/products/{k + 1}", 200)
            elif n == "scraping_low_slow":
                for k in range(150):
                    _rec(records, t + timedelta(seconds=k * 12), ip, None,
                         f"/shop/products/{(k % 50) + 1}?page={k // 50}", 200)
            elif n == "bola_enumeration":
                inst.user = "mallory"
                for k in range(1, 31):
                    _rec(records, t + timedelta(seconds=k), ip, tok, f"/shop/orders/{k}",
                         _order_status(k))
            elif n == "bola_unauthorized_read":
                inst.user = "mallory"
                _rec(records, t, ip, tok, "/shop/me", 200)
                for k, oid in enumerate((2, 3, 4, 5)):
                    _rec(records, t + timedelta(seconds=30 * (k + 1)), ip, tok,
                         f"/shop/orders/{oid}", 200)
            elif n == "token_replay":
                inst.user = "bob"
                inst.ips = set()
                for k in range(5):
                    rip = f"10.{s_idx + 1}.{i + 1}.{100 + k}"
                    inst.ips.add(rip)
                    _rec(records, t + timedelta(seconds=5 * k), rip, tok, "/shop/me", 200)
            elif n == "legit_high_volume":
                inst.user = "alice"
                for k in range(40):
                    path = "/shop/me" if k % 2 == 0 else "/shop/orders/1"
                    _rec(records, t + timedelta(seconds=k * 1.5), ip, tok, path, 200)
            elif n == "repeated_small_set":
                for k in range(60):
                    _rec(records, t + timedelta(seconds=3 * k), ip, None,
                         f"/shop/products/{(k % 3) + 1}", 200)
            elif n == "roaming_user":
                inst.user = "alice"
                inst.ips = set()
                for k in range(4):
                    rip = f"10.{s_idx + 1}.{i + 1}.{50 + k}"
                    inst.ips.add(rip)
                    for j in range(5):
                        _rec(records, t + timedelta(minutes=10 * k, seconds=20 * j), rip, tok,
                             "/shop/me" if j % 2 == 0 else f"/shop/products/{j}", 200)
            elif n == "probe_404_scanner":
                for k, p in enumerate(("/.env", "/wp-login.php", "/admin", "/phpmyadmin",
                                       "/.git/config", "/backup.zip", "/server-status", "/login")):
                    _rec(records, t + timedelta(seconds=2 * k), ip, None, p, 404)
            elif n == "typo_denied_user":
                inst.user = "alice"
                for k, (oid, st) in enumerate(((1, 200), (12, 403), (13, 403), (14, 403), (15, 403))):
                    _rec(records, t + timedelta(seconds=15 * k), ip, tok, f"/shop/orders/{oid}", st)
            elif n == "h_scrape_sequential_walk":
                for k in range(50):
                    _rec(records, t + timedelta(seconds=2 * k), ip, None, f"/shop/products/{k + 1}", 200)
            elif n == "h_bola_slow_probe":
                inst.user = "mallory"
                for k in range(12):
                    _rec(records, t + timedelta(seconds=100 * k), ip, tok, f"/shop/orders/{100 + k}", 404)
            elif n == "h_replay_slow_distributed":
                inst.user = "bob"
                inst.ips = set()
                for k in range(5):
                    rip = f"10.{s_idx + 1}.{i + 1}.{100 + k}"
                    inst.ips.add(rip)
                    _rec(records, t + timedelta(minutes=30 * k), rip, tok, "/shop/me", 200)
            elif n == "h_nat_office":
                # distinct credentials, one shared egress IP
                inst.tokens = {f"{tok}-u{u}" for u in range(6)}
                for u in range(6):
                    for k in range(4):
                        path = "/shop/me" if k == 0 else f"/shop/products/{rng.randint(1, 50)}"
                        _rec(records, t + timedelta(seconds=u * 8 + k * 2), ip, f"{tok}-u{u}", path, 200)
            elif n == "h_partner_sync":
                for k in range(50):
                    _rec(records, t + timedelta(seconds=0.8 * k), ip, tok, f"/shop/products/{k + 1}", 200)
            elif n == "h_two_devices":
                inst.user = "alice"
                inst.ips = {f"10.{s_idx + 1}.{i + 1}.{60 + d}" for d in range(2)}
                for k in range(12):
                    rip = f"10.{s_idx + 1}.{i + 1}.{60 + (k % 2)}"
                    _rec(records, t + timedelta(seconds=20 * k), rip, tok, "/shop/me", 200)
            elif n == "h_owner_reads_own":
                inst.user = "alice"
                for k, oid in enumerate((1, 3, 5, 7, 9)):
                    _rec(records, t + timedelta(seconds=25 * k), ip, tok, f"/shop/orders/{oid}", 200)
            instances.append(inst)

    # Shadow-API traffic: its own IP so it never overlaps a labelled instance.
    t = T0 + timedelta(hours=4 * len(SCENARIOS))
    sh_ip = "10.99.0.10"
    for k in range(3):
        _rec(records, t + timedelta(minutes=k), sh_ip, "bench-shadow", "/shop/me", 200)
        _rec(records, t + timedelta(minutes=k, seconds=5), sh_ip, "bench-shadow",
             "/shop/internal/export", 200)
        _rec(records, t + timedelta(minutes=k, seconds=10), sh_ip, "bench-shadow",
             "/shop/admin/stats", 200)
    _rec(records, t + timedelta(minutes=5), sh_ip, None, "/shop/products/3", 200)
    _rec(records, t + timedelta(minutes=6), sh_ip, None, "/shop/orders/2", 200)
    # Historical noise from Sentinel's own routes (pre-dates self-route skipping).
    _rec(records, t + timedelta(minutes=7), sh_ip, None, "/docs", 200)
    _rec(records, t + timedelta(minutes=7, seconds=1), sh_ip, None, "/openapi.json", 200)
    records.sort(key=lambda r: r["t"])
    return records, instances


def ownership_context(fp_of):
    """Ownership context a controlled deployment would supply to Sentinel.

    ``fp_of(token)`` maps a credential to its stored fingerprint.
    """
    _, instances = build()
    actors = {}
    for inst in instances:
        for tok in inst.tokens:
            if inst.user:
                actors[fp_of(tok)] = inst.user
    return {"resources": {"/shop/orders/{id}": dict(ORDER_OWNERS)}, "actors": actors}
