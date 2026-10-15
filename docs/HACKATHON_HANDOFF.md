# API Sentinel — Hackathon Handoff (CyberCup 6, CC6-IC07)

No credentials in this file. Details and measurements: `docs/PHASE2_REPORT.md`; deployment: `docs/DEPLOYMENT.md`.

## 1. Where things stand

- Branch `jisan`. Phase 2 (including the dashboard) is **committed** as `1e1e515` ("feat: complete API Sentinel Phase 2") on top of `95009f0`; on 15 Oct `origin/jisan` pointed at the same commit. On top of it there are **uncommitted, unpushed** edits: the risk-reason fix in `backend/app/risk_scoring.py`, dashboard review changes (`demo/*`), tests and these docs. `docs/PHASE2_REPORT.md` §16 is the authoritative current-state section.
- Backups (outside the repo, no secrets; checked 15 Oct, see `docs/PHASE2_REPORT.md` §16):
  - `/tmp/api-sentinel-backup-20261014-233322` — Phase 1 close-out (volatile `/tmp`; existence checked, contents not compared).
  - `~/.api-sentinel-backups/phase2-20261015-112752/` — tracked files before Phase 2; **matches `95009f0` exactly** (compared).
  - `~/.api-sentinel-backups/phase2-final-20261015-114344/` and `phase2-dashboard-20261015-120018/` — intermediate Phase 2 snapshots; **neither matches `1e1e515`** (compared: later edits to `analysis.py`, `demo/*` and tests are not in them). The commit itself is the record of the final Phase 2 code.
  - `~/.api-sentinel-backups/live-db-20261015-123000/` — a copy of the live database (existence checked only, not opened).
- Tests: run them from a scratch copy (see `docs/PHASE2_REPORT.md` §16) so the guard in `tests/conftest.py` never sees the live `backend/api_sentinel.db`. Latest result (15 Oct, working tree incl. uncommitted edits): **262 passed** (252 at `1e1e515`).
- Benchmark numbers in `docs/benchmark/` and `PHASE2_REPORT.md` §6 are **outdated until regenerated** (a fresh run differs; see §16). Do not quote them.
- Whether the services listening on :8000/:8080 run Phase 2 code is **not verified** (they were not inspected or restarted). Restart them (§5) to be sure.

- **Phase 3/4 (rate limits, VP quota, gateway/API firewall)** is implemented as further uncommitted edits on top of `1e1e515`; see `docs/GATEWAY_AND_RATE_LIMITS.md` for design, configuration, limits, verification and the isolated demo. A verified pre-Phase-3/4 backup is at `~/.api-sentinel-backups/pre-phase34-20261015-155616/`.

## 2. Architecture (changes since Phase 1 in bold)

- `backend/app/main.py` — `create_app(db_path, enable_capture, fp_secret, enable_demo, api_key, **env, spec_dir, ownership, clock**)`; **`app` is built lazily** so importing the module never creates a database; **access-log redaction filter**.
- `config.py` — settings from env; **`SENTINEL_ENV`, `SENTINEL_SPEC_DIR`, `SENTINEL_OWNERSHIP_PATH`; default bind 127.0.0.1; `validate_environment` (production fails closed)**.
- `capture.py` — safe request summaries (no bodies/tokens/headers); keyed-HMAC credential fingerprint.
- `discovery.py` — inventory, OpenAPI comparison; **segment-level path normalization, single list of Sentinel's own routes, generic spec errors, 2 MiB cap**.
- `analysis.py` — pure detectors: scraping (**burst gated on ≥ 5 distinct paths + low-and-slow**), BOLA enumeration, token replay (**requires concurrent multi-IP use**), **confirmed BOLA from ownership context**, explicit-context cases.
- `risk_scoring.py` — unchanged weights/caps; findings carry `metadata.reasons`; the Low/Medium/High sentence is derived from the **final** (escalated) score via `guidance()` and is the last reason.
- **`timeutil.py`** (naive-UTC normalization), **`ownership.py`** (context loader), **`maintenance.py`** (optional retention CLI).
- `storage.py` — SQLite; internal-route rows hidden at read time; UTC-aware alert upsert.
- Routes — `shadow.py` confines `spec_path`; `health.py` checks storage; findings use a clock-anchored live window.
- **`ratelimit.py`** (per-endpoint quotas, server-side identity, VP = 21x), **`principals.py`** (operator fingerprint registry; no default accounts), **`gateway.py`** (`/gateway/*` reverse proxy / API firewall), **`routes/policy.py`** (`GET /api/rate-limits`, `GET /api/gateway-events`); `storage.py` adds the `gateway_events` audit table.
- `backend/benchmark/` — labelled synthetic benchmark; `backend/simulator/` — traffic driver, shop spec, **`ownership.py`**.
- `demo/` — dashboard (`index.html`, `dashboard.css`, `dashboard.js`, no framework; includes a "What is detected and what the risk score means" panel) + key-holding localhost proxy `serve.py` (static allowlist of those 3 files, CSP and other security headers, same key/route/CSRF controls as before).

## 3. Detections (current)

- Scraping: > 10 requests/60 s **and** ≥ 5 distinct paths, or > 20 distinct paths/60 s, or > 100 requests with ≥ 20 distinct paths in 3600 s (low-and-slow). Actor = client IP.
- BOLA enumeration (attempt signal): > 10 distinct IDs, ≥ 50 % 401/403/404, 300 s, per actor + method + template.
- Confirmed BOLA: 2xx read of an object owned by another user, only with ownership context.
- Token replay: one credential fingerprint with ≥ 4 IPs that switched within 60 s of its previous request (inside 3600 s).
- Shadow APIs: observed routes missing from an OpenAPI **JSON** spec; 404/405-only probes and Sentinel's own routes excluded. Demo has two: `/shop/internal/export`, `/shop/admin/stats`.
- Score: base weight (BOLA 35, scraping 30, replay 35) + magnitude (+10/+20/+30 at 3×/6×/12×) + context (+10 write method, +10 sensitive path), capped at 100.

## 4. Authentication

- `SENTINEL_API_KEY` (≥ 32 chars) sent as `X-Sentinel-Key`; constant-time compare. Key set ⇒ every route except `GET /api/health` needs it. Unset ⇒ development only: reads open, writes 503.
- `SENTINEL_ENV=production` additionally requires `SENTINEL_FP_SECRET` (≥ 32 chars) and forbids the demo shop; the process refuses to start otherwise.
- The dashboard proxy reads the key from its own environment, adds it only to allowlisted Sentinel routes, and enforces Host/Origin/Content-Type/size limits for writes.
- `demo/serve.py` is a **localhost demo convenience, not a security boundary**: it is not a firewall, WAF or production reverse proxy, and anyone who can reach its port acts with the admin key. A real deployment puts Sentinel behind a reverse proxy (TLS, forwarded client IP) and a firewall, as in `docs/DEPLOYMENT.md` §2 and §5, and does not run this proxy.

## 5. Demo startup (replace `...` with generated values; never commit them)

**Preferred:** `scripts/run-local.sh start <env-file>` starts a backend and dashboard proxy from the same checkout,
checks that their versions match, and reports gateway/VP status. Template: `docs/examples/local.env.example`; details
in `docs/GATEWAY_AND_RATE_LIMITS.md` §8. The manual commands below still work, but a backend or proxy started earlier
keeps running its old code until restarted (the dashboard then shows "Version mismatch").

Backend, from `backend/` (the ownership file enables confirmed BOLA in the demo):

```bash
cd backend
export SENTINEL_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export SENTINEL_FP_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
python3 -m simulator.ownership > /tmp/sentinel-ownership.json        # fingerprints + owners, no tokens
ENABLE_DEMO_TARGET=true OPENAPI_SPEC_PATH="$PWD/simulator/shop-openapi.json" \
  SENTINEL_OWNERSHIP_PATH=/tmp/sentinel-ownership.json \
  python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Dashboard, from the repo root, same key:

```bash
SENTINEL_API_KEY="$SENTINEL_API_KEY" BACKEND_URL=http://127.0.0.1:8000 python3 demo/serve.py   # http://127.0.0.1:8080
```

Traffic and checks: `python3 -m simulator.run` (from `backend/`), then "Run scan" in the dashboard or `curl -X POST -H "X-Sentinel-Key: $SENTINEL_API_KEY" http://127.0.0.1:8000/api/scan`. The spec box in the dashboard only accepts files inside the spec directory (the folder of `OPENAPI_SPEC_PATH`).
Use the **same** `SENTINEL_FP_SECRET` when generating the ownership file and starting the backend. Restarting the backend with a different fingerprint secret makes old stored fingerprints stop matching.

Browser check: open http://127.0.0.1:8080 → Generate sample traffic → Run scan. The page's own sample traffic gives 2 shadow APIs and **one scraping alert only**. For the confirmed-BOLA (needs the ownership file), BOLA-enumeration and token-replay alerts, also run `python3 -m simulator.run` from `backend/` (set `SENTINEL_URL` if the backend is not on :8000), then Run scan again. Change an alert's status/note → Save. Stop the backend to see the error states. Keep the proxy on 127.0.0.1.

Benchmark: `cd backend && python3 -m benchmark.run --markdown -` (isolated; never touches your database).

## 6. Restart checklist

1. `git status`, `git rev-parse --short HEAD` (expect `1e1e515` or a later commit of yours).
2. Stop the old backend/dashboard processes, then start them as in §5. Existing database rows and the acknowledged `scraping` alert are kept. Historical `/docs` and `/openapi.json` rows stay in the file but no longer appear.
3. `curl http://127.0.0.1:8000/api/health` → `{"status":"ok",...,"database":"ok"}`.
4. If the dashboard shows 401/503, its key differs from the backend's; restart it with the backend's key. Do not disable auth to work around it.
5. Keep `ENABLE_DEMO_TARGET=true` on the demo machine only.

## 7. Known limitations

See `docs/PHASE2_REPORT.md` §12. Highlights: synthetic, self-authored benchmark; slow distributed token abuse and slow ID probing are missed; many users behind one IP can look like one scraper; confirmed BOLA needs ownership data you supply; JSON OpenAPI only; no separate `frontend/` app (not verified as required; the demo dashboard was upgraded instead, see `docs/PHASE2_REPORT.md` §15).
