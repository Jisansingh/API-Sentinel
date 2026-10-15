# API Sentinel — Phase 3 (rate limits) and Phase 4 (gateway / API firewall)

Status: implemented and tested locally on synthetic traffic. **Not production-ready**: no load test, no
penetration test, no multi-process or multi-host run, and the identity source is a static operator file
(see §2). Code: `backend/app/ratelimit.py`, `backend/app/principals.py`, `backend/app/gateway.py`,
`backend/app/routes/policy.py`. Tests: `backend/tests/test_rate_limit.py`, `backend/tests/test_gateway.py`.

## 1. What it does

- **Every endpoint has its own limit** per identity per window: Sentinel's API, the demo shop and every gateway
  route. Exceeding it returns `429` with `Retry-After` (seconds to the next window), `X-RateLimit-Limit` and
  `X-RateLimit-Remaining`; allowed responses carry the two `X-RateLimit-*` headers too.
- **VP quota = exactly 21 × the endpoint's normal quota**, same window (normal 50 → VP 1,050). The multiplier is a
  constant (`VP_MULTIPLIER`), not configurable.
- **Gateway** (`/gateway/<upstream path>`): forwards only configured method + path templates to one configured
  upstream, with SSRF, size, timeout, header and redirect protections (§5).
- **Audit trail**: 429s, firewall blocks, every VP request, traffic from principals labelled `security_scan` or
  `authorized_test`, and ignored role-claim headers go to the `gateway_events` table, shown in the dashboard's
  **Access control** panel and at `GET /api/gateway-events`. Effective quotas: `GET /api/rate-limits`.
- Gateway traffic still goes through capture, so inventory, shadow APIs, abuse detection, risk scoring and alerts
  work on it (recorded under the upstream path, without `/gateway`). VP traffic is analysed like anyone else's.

## 2. Identity (who gets which quota)

Sentinel has **no identity provider**. Identity is decided server-side, in this order:

1. **Registered principal**: the request's `Authorization` (or `X-API-Key`) value has a keyed fingerprint
   (HMAC-SHA256 with `SENTINEL_FP_SECRET`, the same one capture already uses) listed in
   `SENTINEL_PRINCIPALS_PATH` → own bucket, role `user` or `vp`.
2. **Sentinel admin**: a valid `X-Sentinel-Key` → the `admin` bucket, normal quota.
3. **Everyone else**: the client address (IPv6 grouped by /64). Unregistered credentials are ignored for bucketing,
   so inventing tokens does not create fresh quotas.

Headers such as `X-Role`, `X-User`, `X-Forwarded-User`, `X-VP` are **never** used for identity; when present on a
non-VP request they are logged as `unverified_privilege_claim`. There is **no default principal and no default VP**:
without the file nobody is a VP. The file holds fingerprints only, never credentials:

```json
{"principals": [
  {"id": "jane", "fingerprint": "<32 hex>", "role": "vp"},
  {"id": "scanner-1", "fingerprint": "<32 hex>", "role": "user", "purpose": "security_scan"}
]}
```

Make a fingerprint without putting the credential in argv or shell history (credential read from stdin):

```bash
SENTINEL_FP_SECRET=... python3 -m app.principals fingerprint      # then type/paste e.g.:  Bearer <token>
```

**Missing integration (honest gap):** recognising a credential is not the same as validating it. The gateway knows a
credential belongs to a principal because its fingerprint is listed; the **upstream still authenticates** the request
(and can still reject a revoked token). A real deployment should replace the static file with an IdP integration
(e.g. verified OIDC/JWT claims with a `vp` role or group), keep roles server-side, and add revocation. Not implemented.

## 3. Rate-limit configuration

| Setting | Default | Notes |
|---|---|---|
| `window_seconds` | 60 | Fixed window aligned to the Unix epoch, 1–86,400. |
| `default_limit` | 60 | Only for gateway routes without an explicit limit (shown as source `default_limit`). |
| `limits` | see below | `{"METHOD /template": n}`, 1–100,000. A key that matches no real endpoint is a **startup error**. |

Built-in per-endpoint defaults (per 60 s window, normal / VP):

| Endpoint | Normal | VP |
|---|---|---|
| `GET /api/health` | 120 | 2,520 |
| `GET /api/inventory`, `GET /api/findings`, `GET /api/alerts`, `GET /api/gateway-events` | 60 | 1,260 |
| `GET /api/shadow-apis`, `PATCH /api/alerts/{alert_id}`, `GET /api/rate-limits` | 30 | 630 |
| `POST /api/scan` (analyses all captures) | 10 | 210 |
| `GET /shop/products/{product_id}` (demo shop) | 300 | 6,300 |
| `GET /shop/me`, `GET /shop/orders/{order_id}` (demo shop) | 120 | 2,520 |
| `GET /shop/internal/export`, `GET /shop/admin/stats` (demo shop) | 60 | 1,260 |
| `GET /gateway/<route>` | `default_limit` unless set | 21 × |
| `ANY /gateway/* (no matching route)` (malformed/unknown gateway requests) | `default_limit` | 21 × |

The demo-shop values are high on purpose so the simulator's attack scenarios (≤ 40 requests per client) still reach
the detectors. Example: `docs/examples/rate-limits.demo.json`.

### Guarantees and limits of the limiter

- **Atomic in one process**: check-and-count runs under one lock (tested with 32 threads and with parallel HTTP
  requests; the E2E run sent 1,051 parallel VP requests → exactly 1,050 allowed).
- **Fixed window**: up to 2 × the limit can pass across one window boundary. Use a sliding window if that matters.
- **Per process, in memory**: counters reset on restart; with several uvicorn workers or hosts each keeps its own
  counters (effective limit × workers). Run **one** worker, or add a shared store (e.g. Redis) — not implemented.
- **Memory bound**: counters are dropped at each window boundary; at most 100,000 anonymous (IP) buckets per window,
  after which *new* IPs get 429 (fail closed) while existing IPs, principals and admin keep working.
- **IP fallback weaknesses**: users behind one NAT share a quota; an attacker with many addresses (botnet, large IPv6
  allocations beyond a /64) gets many quotas. Registered principals avoid both.
- **Forwarded headers**: uvicorn trusts `X-Forwarded-For` from `--forwarded-allow-ips` (default **127.0.0.1**). Any
  client connecting from a trusted address can then choose its own IP bucket — measured in the E2E run: a loopback
  client escaped a 429 with a forged `X-Forwarded-For` until the gateway ran with `--no-proxy-headers`. Run the
  gateway with `--no-proxy-headers` when clients connect directly, or with `--forwarded-allow-ips=<your proxy only>`
  behind a reverse proxy that **overwrites** the header. (The demo simulator relies on forwarded headers to fake
  client IPs, so do not point it at a gateway started with `--no-proxy-headers` and expect distinct clients.)
- Unrouted requests (404 outside `/gateway`) and FastAPI's `/docs`, `/redoc`, `/openapi.json` are not limited.

## 4. Gateway configuration (`SENTINEL_GATEWAY_CONFIG`)

```json
{"upstream": "https://api.internal.example:8443",
 "allow_private_network": false,
 "connect_timeout_seconds": 3, "total_timeout_seconds": 10,
 "max_request_body_bytes": 1048576, "max_response_body_bytes": 5242880,
 "routes": [
   {"method": "GET", "path": "/shop/products/{id}", "auth": "none"},
   {"method": "GET", "path": "/shop/orders/{id}", "auth": "principal", "roles": ["user", "vp"]}
 ]}
```

- `upstream`: `http`/`https`, host, optional port; no credentials, path, query or fragment.
- `routes`: methods `GET POST PUT PATCH DELETE`; templates of literal segments (`A-Z a-z 0-9 . _ ~ -`) and `{name}`.
  `auth` defaults to **`principal`** (fail closed); `roles` defaults to both roles. A VP is checked like any other
  principal: a route with `"roles": ["user"]` refuses a VP (tested).
- Startup refuses: unknown keys, bad URLs, disallowed literal addresses, duplicate routes, bad timeouts/sizes,
  `principal` routes without a principals file, a principals file without `SENTINEL_FP_SECRET`.

## 5. Gateway protections

| Threat | Control | Tested |
|---|---|---|
| Client picks host/port/scheme | Upstream fixed in config; client supplies only validated path segments (rebuilt) and a query string | yes |
| SSRF to metadata/internal | Every resolved address must pass: link-local (169.254/16, fe80::/10), multicast, unspecified, reserved and known metadata IPs (`100.100.100.200`, `fd00:ec2::254`, `192.0.0.192`) always refused; loopback/private only with `allow_private_network`; plain `http` only to non-public addresses | yes (unit + per-request) |
| DNS rebinding | Resolve per request, refuse if **any** answer is disallowed, connect to the checked IP (pinned); TLS still verifies the configured hostname | yes, incl. TLS name check |
| Redirect to internal | Redirects never followed; 3xx → 502 | yes |
| Path tricks | Raw path must be ASCII `A-Z a-z 0-9 . _ ~ -` segments; `//`, `\`, trailing `/`, `.`/`..` segments, encoded `/ \ . NUL` refused (400) | yes |
| Oversized input | URL ≤ 2,048 bytes (414), ≤ 64 headers / 16 KiB (431), body cap incl. chunked (413), response cap (502) | yes |
| Slow upstream | Connect timeout + overall deadline (504) | yes |
| Header smuggling/leaks | Request header allowlist (`Accept`, `Accept-Language`, `Content-Type`, `Authorization`, `X-API-Key`, `User-Agent`); `X-Sentinel-Key`, cookies and client `X-Forwarded-For` never forwarded; `X-Forwarded-For` set to the real peer; response header allowlist (no `Set-Cookie`, `Server`, `Location`) | yes |
| Error leakage | Generic JSON errors; upstream 5xx bodies replaced by `{"detail": "upstream error"}` | yes |
| Probing floods | Malformed and unknown routes share one per-identity quota; they are logged as events, **not** captured as API traffic (so they cannot invent shadow APIs) | yes |

Not implemented: TLS client certificates or a shared secret towards the upstream, cookie-based upstream auth (cookies
are dropped), WebSockets/streaming, multiple upstreams, request body inspection (WAF rules), HEAD/OPTIONS routes.

## 6. Deployment controls you must add (code cannot enforce them)

- **No direct path to the upstream**: bind it to a private interface and firewall it so only the gateway host can
  reach it; ideally also require mTLS or a gateway-only credential at the upstream. Otherwise clients simply bypass
  the gateway (in the local demo the upstream on :9000 is reachable directly — demo only).
- **TLS**: terminate TLS in front of Sentinel (reverse proxy); use `https` upstreams across any untrusted network.
  Public upstreams are refused over plain `http`.
- **Forwarded headers**: see §3 (`--no-proxy-headers` / `--forwarded-allow-ips`).
- **One process** per gateway instance unless a shared counter store is added (§3).
- **Upstream limits**: the upstream sees the gateway as one client; its own per-IP limits must allow the gateway's
  aggregate traffic (the E2E run hit the demo upstream's 300/min shop limit until it was raised with
  `docs/examples/upstream-rate-limits.demo.json`).
- `SENTINEL_ENV=production` still requires the admin key and fingerprint secret and refuses the demo shop.

## 7. Logging, privacy and retention

- Log lines (`api_sentinel.ratelimit`) and `gateway_events` rows hold: window, endpoint **template**, decision,
  reason, status, identity kind, principal id, role, purpose, client IP, count. Never tokens, the admin key,
  fingerprints, raw paths, query values or bodies (tests scan the database file and server logs for planted secrets;
  the E2E run found 0 occurrences of the key, fingerprint secret or VP token in logs and databases).
- Rows are aggregated per (window, endpoint, decision, reason, identity), so floods increase `count` instead of rows.
- Retention is manual, dry-run by default: `python3 -m app.maintenance --db <file> --events-days 30 [--apply]`.
- Upgrading: `init_db` adds the `gateway_events` table to an existing database at startup (additive; no existing
  table is changed).

## 8. Starting a compatible backend + dashboard (`scripts/run-local.sh`)

The backend and the dashboard proxy load their code once, at start-up, while the dashboard page is read from disk on
every request. A process started before an update therefore serves an old API to a new page. This happened on 15 Oct:
the live :8000/:8080 processes predated Phase 3/4, so the Access control panel showed `HTTP 404`.

**Safeguards**
- `GET /api/health` reports `api_revision` (`app/config.py` `API_REVISION`).
- `/api/proxy-status` reports `proxy_revision` (`demo/serve.py` `PROXY_REVISION`).
- The page checks both against `REQUIRED_API_REVISION` / `REQUIRED_PROXY_REVISION`. On a mismatch the header shows
  **Version mismatch**, naming the stale process, and the affected panel repeats it instead of a bare status code.
- Tests fail if the three constants drift apart, or if the page calls an endpoint the app does not register.

**Repeatable start-up** of a matching pair from this checkout:

```bash
cp docs/examples/local.env.example ~/sentinel-local.env && chmod 600 ~/sentinel-local.env
# edit it: two generated secrets, an absolute NEW test database, ports, optional Phase 3/4 files
scripts/run-local.sh start  ~/sentinel-local.env    # refuses busy ports; never kills anything it did not start
scripts/run-local.sh status ~/sentinel-local.env    # revisions, key accepted, gateway on/off, principals, VP count
scripts/run-local.sh stop   ~/sentinel-local.env    # stops only the PIDs it recorded
```

The script refuses to start when:
- the env file is inside the repository, or readable by others;
- `DATABASE_URL` is not an absolute path;
- a port is in use;
- the app rejects the configuration (e.g. `SENTINEL_ENV=production` without the key/secret, or with the demo shop on).

**What it uses**
- uvicorn runs with `--no-proxy-headers` unless `TRUST_PROXY_IPS` names your reverse proxy.
- Logs and PID files go to `<env-file>.run/`.
- Secrets are never printed.

**Status output**

Its status output states plainly when the gateway is off, when no VP principal exists ("nobody gets the VP
quota"), and whether the demo shop is mounted. The backend log carries the same VP warning.

**Demo shop:** "Generate sample traffic" calls the deliberately vulnerable shop (`/shop/*`), which exists only when
the backend starts with `ENABLE_DEMO_TARGET=true`. The template turns it on for development. Production refuses it,
and the script stops before starting anything if both are set. Without it, every sample request returns 404 and the
dashboard says the shop is not mounted. Set `OPENAPI_SPEC_PATH=<repo>/backend/simulator/shop-openapi.json` as well, so
the shadow-API panel can compare against the shop's published spec.

**Existing services**

Services that were started by hand (like the live :8000/:8080) are not managed by the script. Restart them yourself
from the updated source, or stop them and use the script on those ports.

### Demo with the gateway

Run the demo shop as the protected upstream (own database; higher shop limits because it sees the gateway as one
client), then add the Phase 3/4 files to the env file:

```bash
cd backend
( exec env -u SENTINEL_API_KEY -u SENTINEL_FP_SECRET ENABLE_DEMO_TARGET=true \
    DATABASE_URL=sqlite:///$HOME/sentinel-upstream.db \
    SENTINEL_RATE_LIMITS_PATH=$PWD/../docs/examples/upstream-rate-limits.demo.json \
    python3 -m uvicorn app.main:app --host 127.0.0.1 --port 9000 ) &

# principals: fingerprints only; credentials are typed on stdin, never in argv or files
set -a; . ~/sentinel-local.env; set +a
ALICE_FP=$(printf 'Bearer demo-alice-token\n' | python3 -m app.principals fingerprint)
VP_FP=$(python3 -m app.principals fingerprint)          # paste "Bearer <your VP test token>", Enter
printf '{"principals":[{"id":"alice","fingerprint":"%s","role":"user"},{"id":"demo-vp","fingerprint":"%s","role":"vp"}]}\n' \
  "$ALICE_FP" "$VP_FP" > ~/sentinel-principals.json && chmod 600 ~/sentinel-principals.json
```

In `~/sentinel-local.env` set (absolute paths): `SENTINEL_GATEWAY_CONFIG=<repo>/docs/examples/gateway.demo.json`
(its upstream is `127.0.0.1:9000`), `SENTINEL_PRINCIPALS_PATH=$HOME/sentinel-principals.json`,
`SENTINEL_RATE_LIMITS_PATH=<repo>/docs/examples/rate-limits.demo.json`,
`OPENAPI_SPEC_PATH=<repo>/backend/simulator/shop-openapi.json`. Then `scripts/run-local.sh start ~/sentinel-local.env`;
status should show `gateway ON` and `1 with VP quota`.

**Try against the backend port**

| Request | Expected |
|---|---|
| `/gateway/shop/products/1`, 51st call in a minute | 429 with `Retry-After`, `X-RateLimit-Limit: 50` |
| The same with `-H "Authorization: Bearer <VP token>"` | 1,050 per minute |
| `-H "X-Role: vp"` | Ignored, and listed under "claim ignored" |
| `/gateway/shop/orders/1` without, then with, `-H "Authorization: Bearer demo-alice-token"` | 401, then 200 |
| `/gateway/shop/internal/export` as alice | 403 (VP-only route) |
| `/gateway/shop/admin/stats` | 404 (not exposed) |

Then **Run scan** in the dashboard: gateway traffic produces scraping alerts like direct traffic.

## 9. Verified on 15 Oct (isolated ports 9110–9112, scratch databases)

- **Plain start (no Phase 3/4 files):** gateway off, 0 principals, "nobody gets the VP quota", 9 limited endpoints.
- **Full config:**
  - 14 limited endpoints with 7 distinct normal limits, every VP limit exactly 21×.
  - Anonymous: 50 OK, then 429 with `Retry-After`.
  - `X-Role: vp` and a forged `X-Forwarded-For` gave no extra quota.
  - VP: 1,051 parallel requests gave exactly 1,050 OK and one 429 (`X-RateLimit-Limit: 1050`).
  - A user was refused the VP-only route with 403, even with `X-Role: vp`.
  - The generated key, fingerprint secret and both tokens appeared 0 times in logs, databases and config files.
- **Browser (headless Chrome):**
  - Matching pair: panel loaded.
  - Old backend + new proxy: "Version mismatch: the backend …".
  - Old proxy process serving the new page: "Version mismatch: the dashboard proxy …".
  - No console errors or CSP violations in any case.
- **Not verified:** the live :8000/:8080 services (not restarted), other browsers, multi-worker deployments.
