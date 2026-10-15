# Integration decisions

Source workspaces (read-only; never modified by the integrator):
- Discovery side (capture, inventory, shadow APIs, `docs/backend-contract.md`):
  `/Users/jssingh/Claude-Workspace/api-sentinel`, branch `main`.
- Security side (abuse detection, risk scoring, `docs/security-contract.md`):
  `/Users/jssingh/.superset/worktrees/api-sentinel/muddled-moonstone-526199e2`,
  branch `api-sentinel-backend-526199e2`.
- Integration workspace (this one):
  `/Users/jssingh/.superset/worktrees/api-sentinel/interesting-ursinia-bd2de5ae`,
  branch `api-sentinel-integration-bd2de5ae`. Base commit `4e81601` was an
  empty skeleton; all app files were populated by copying from the two
  sources above (no source worktree was written to).

## 1. Findings shape (contracts disagreed)

- `backend-contract.md` §4 proposes `DetectionResultIn` with
  `severity: low|medium|high|critical` + `confidence: 0.0–1.0`, no numeric score.
- `security-contract.md` defines `RiskScore` with numeric `score: 0–100`.
- The task requires `risk score 0–100 (higher = more dangerous)` plus
  detection type, endpoint/resource, reason, timestamp, safe metadata.

Decision: the authoritative finding is the new additive `schemas.Finding`
(`detection_type`, `endpoint`, `risk_score: 0–100`, `reason`, `timestamp`,
`metadata`). The numeric score wins because the task mandates it.
`DetectionResultIn` is kept untouched for backward compatibility but is not
used by the pipeline, avoiding a second severity vocabulary and duplicate
scoring.

## 2. Findings endpoint (contract left open)

`backend-contract.md` §6.1 lists `POST /api/findings` + `GET /api/findings`
as undecided (including whether findings persist).

Decision: implement read-only `GET /api/findings` only
(`app/routes/findings.py`). It analyzes the current SQLite captures on each
call — no persistence layer, no new tables, nothing to migrate. `POST` is
deferred: accepting raw tokens/events over HTTP would widen the secrets
surface for no hackathon benefit.

## 3. BOLA / token-replay inputs (key mismatch, resolved safely)

Captured records contain only `method, path (sanitized), status_code,
duration_ms, client_ip, created_at`. They deliberately contain NO user IDs,
auth maps, tokens, bodies, or headers. The security detectors require
`user_id + authorized_resource_ids` (BOLA) and `token + user_id + ip +
timestamp` (token replay).

Decision: never invent these from traffic. `app/analysis.py` exposes:
- `analyze_scraping_from_captures()` — the only detector fed by capture
  data (actor = `client_ip`, resource = raw path without query, timestamp =
  server `created_at`). Thresholds are configurable query params defaulting
  to the security contract (`60s / 10 reqs / 20 distinct`).
- `analyze_bola_cases()` / `analyze_token_replay_cases()` — take explicit
  caller-supplied context; with no context they return no findings (safe
  default, no false positives). Token helpers fingerprint immediately via
  `TokenReplayDetector.fingerprint_token()`; raw tokens never appear in
  findings (only the 16-char fingerprint in metadata).

## 4. Scraping resource identity

Normalized paths (`/users/{id}`) would collapse a `/users/1…/users/100`
scrape into one object and miss the distinct-object threshold. Decision: feed
the detector raw paths (query stripped, IDs intact) so distinct counting
works; report the finding's `endpoint` as the actor's most frequent
normalized path (lexicographically-smallest tie-break) so findings still join
cleanly with inventory rows.

## 5. Module boundaries (no duplication, no cycles)

- Kept verbatim: `capture.py`, `config.py`, `discovery.py`, `storage.py`,
  `schemas.py` (additive `Finding`/`FindingsResponse` only),
  `routes/health.py`, `routes/inventory.py`, `routes/shadow.py`,
  `abuse_detection.py`, `risk_scoring.py`.
- New: `app/analysis.py` (pure pipeline, no FastAPI imports),
  `app/routes/findings.py` (thin HTTP wrapper). `main.py` only adds the
  findings router.
- Left intentionally empty (reserved, not duplicated): `app/shadow_detection.py`
  (behavioral shadow-IP work per backend contract, distinct from
  spec-comparison shadow APIs), `app/routes/alerts.py`, `app/routes/analytics.py`.
- Each finding scores exactly one signal through `RiskScorer` (35/30/35);
  breakdowns sum to the score, so nothing is double-counted.

## 6. Determinism and safety

- Findings sorted by `(detection_type, endpoint)`; per-actor endpoint choice
  and timestamp reuse (`max(created_at)`) are deterministic. Wall-clock time
  is used only as a fallback when a record has no timestamp.
- Malformed/empty inputs (None, `{}`, bad dates, missing auth fields) are
  skipped, never flagged, never 500. Empty DB returns HTTP 200 with
  `{"items": [], "total_findings": 0}`.
- No frontend, LLM, or external API testing was added. Tests hit only the
  in-process demo API (`testclient`).

## 7. Carried-over open questions (from backend-contract §6, still open)

- Should inventory exclude our own monitoring routes (`/api/health`)? Kept
  as-is (included); out of scope for this integration.
- Risk-score annotation of inventory rows in place vs separate map: chose
  separate `GET /api/findings` map; inventory untouched.
- OpenAPI YAML support: still JSON-only, per the discovery implementation.

## 8. P1 — capture hygiene and actor identity

- Capture skips Sentinel's own analysis/dashboard routes
  (`capture.SELF_ROUTE_PREFIXES`: inventory, shadow-apis, findings, alerts,
  scan, docs/redoc/openapi.json). Dashboard polling previously became
  "traffic" and could trigger scraping findings. `/api/health` is still
  captured: existing tests use it as stand-in monitored traffic.
- New nullable `captured_requests.actor_fp`: keyed HMAC-SHA256 (32 hex) of
  the `Authorization` or else `X-API-Key` value, key from
  `SENTINEL_FP_SECRET` (>= 32 chars, held as `SecretStr`, never logged).
  Missing/short key => NULL fingerprints and client IP stays the actor.
  Existing databases gain the column via an additive `ALTER TABLE`.
- Shadow APIs exclude routes whose every observed status is 404/405
  (`discovery.is_unresolved_route`), in both spec-loaded and spec-missing
  responses. Trade-off: an undocumented route that only ever returns 404
  (e.g. every lookup misses) is not reported.

## 9. P2 — capture-based detectors

- `bola_enumeration`: per (actor, method, ID template), rolling 300 s window
  (own window, after Akto's ParamEnumerationDetector, so slow probes under
  the 60 s scraping limit are caught): > 10 distinct IDs AND >= 50% of
  responses 401/403/404. Bulk all-200 reads stay "scraping" — existing
  tests pin that, and it keeps the two signals separate. This is an
  attempt signal; confirmed BOLA still needs explicit ownership context.
- `token_replay` (metadata `source: capture`): one `actor_fp` from > 3
  distinct client IPs within 3600 s. Anonymous requests are ignored.
- Scraping keeps its rolling "latest window" semantics (pinned by
  `test_scraping_finding_expires_once_burst_leaves_rolling_window`);
  persistence comes from stored alerts (P3), not from re-scanning history.
- Client IP is the direct peer. Behind a proxy, run uvicorn with
  `--proxy-headers --forwarded-allow-ips=<proxy>`; otherwise every client
  looks like the proxy and IP-based signals collapse.

## 10. P3 — persistent alerts

- New `alerts` table (created by `init_db`, additive). Unique key
  `(detection_type, actor, endpoint)`; actor = `analysis.alert_actor`
  (enumeration actor, token fingerprint, client IP, or user id).
- `POST /api/scan` is the only writer: runs the capture pipeline with
  default thresholds and upserts. Same evidence (finding timestamp not newer
  than `last_seen`) => `unchanged`; newer evidence => `occurrences + 1`,
  `last_seen` updated, `resolved` reopens to `open`, `ignored` /
  `acknowledged` keep their status (suppression, like Metlo/Akto triage).
- `GET /api/alerts[?status=]` and `GET /api/findings` never scan or write.
  `PATCH /api/alerts/{id}` sets `status` (open|acknowledged|resolved|ignored)
  and an optional `note` (<= 500 chars).
- Limits: alerts only capture what a scan saw; a burst that leaves the
  rolling window before any scan runs is missed. No auth on these routes
  (true for the whole Sentinel API today). No retention/archiving yet.

## 11. P5 — demo target and simulator

- `app/routes/demo_shop.py`: a DELIBERATELY VULNERABLE shop API (BOLA on
  `GET /shop/orders/{id}`, undocumented `GET /shop/internal/export`). Mounted
  only with `ENABLE_DEMO_TARGET=true` / `create_app(enable_demo=True)`;
  absent by default (tested). Tokens are fixed demo strings.
- `backend/simulator/run.py` (stdlib only) drives normal use, scraping,
  BOLA enumeration and token replay; `simulator/shop-openapi.json` is the
  published spec. Client IPs are simulated via `X-Forwarded-For`, which
  uvicorn trusts from 127.0.0.1 by default (verified against a live server).

## 12. P4 — explainable risk escalation

- `RiskScorer.escalate`: base detector weight + `magnitude` (observed /
  threshold: >=3x +10, >=6x +20, >=12x +30) + `context` (+10 write method,
  +10 `admin|internal|export|debug` path segment), capped at 100. Bonuses are
  separate breakdown keys, so detector keys keep their base weight and all
  breakdown values sum to the score.
- Starts at 3x so existing tests that pin base scores at 1.5x and 2.5x stay
  valid. Applied to capture-based detectors only; explicit-context BOLA and
  token-replay cases keep their fixed weights.

## 13. Review fixes

- `/api/health` is no longer captured (health monitors polling every few
  seconds would trip the scraping rule). Tests that used it as stand-in
  traffic now use the `target_app` fixture in `tests/conftest.py`
  (`/target/ping`, `/target/items/{id}`).
- Sentinel API auth (`app/auth.py`): `SENTINEL_API_KEY` (>= 32 chars, else
  startup fails) sent as `X-Sentinel-Key`, constant-time compare. With a
  key: all Sentinel routes except `/api/health` require it. Without: reads
  open (dev; startup warning), writes 503 (fail closed). The `demo/`
  dashboard proxy sends no key, so it works only with the key unset.
- `POST /api/scan` evaluates scraping over every window
  (`analyze_scraping_from_captures(all_windows=True)`): each actor's most
  recent breaching window is recorded even if quiet traffic followed and no
  scan ran during the burst. `GET /api/findings` keeps rolling semantics.

## 14. Dashboard proxy authentication (`demo/serve.py`, `demo/index.html`)

- The proxy reads `SENTINEL_API_KEY` from its own environment and adds
  `X-Sentinel-Key` only to allowlisted Sentinel routes (GET inventory,
  findings, shadow-apis, alerts; POST /api/scan; PATCH /api/alerts/{id}).
  Other GET /api/* paths (sample monitored traffic) are proxied without it;
  other write routes are not proxied (404). Client-sent headers are never
  forwarded, so a browser cannot inject or read the key.
- The proxy holds credentials, so writes require: allowed Host (DNS
  rebinding), `Origin` equal to the dashboard origin (CSRF), JSON
  content type (415 otherwise; forces a CORS preflight cross-site), and a
  body <= 4 KiB (413). Startup prints only "configured"/"NOT set".
- The dashboard gained "Run scan" and an alerts table with per-row status
  triage; all rendering stays DOM/textContent-based.
- Trust boundary: anyone who can reach the proxy port on this machine acts
  with the admin key. It binds to 127.0.0.1 only; do not expose it.

## 15. Dashboard sample traffic uses the demo shop

- "Generate sample traffic" replays a JSON plan embedded in `index.html`
  (`<script id="sample-traffic">`): alice's `/shop/me` and own order, 25
  anonymous product reads, one query-token read (redaction demo), and an
  authenticated `GET /shop/internal/export` (200, absent from
  `simulator/shop-openapi.json`) => one shadow API. The old `/api/users/{n}`
  and `/api/admin/export` targets 404'd and stopped counting as shadow APIs
  after the 404/405 filter.
- `serve.py` proxies `GET /shop/*` as monitored traffic: it forwards only
  the client's `Authorization` header and never adds the Sentinel key.
  Tokens in the plan are the public fixtures from `demo_shop.py` (a test
  pins them to `DEMO_USERS`).
- `tests/test_demo_proxy.py` replays the exact embedded plan through the
  real proxy to a real backend and asserts the shadow set is exactly
  `{GET /shop/internal/export}`.
