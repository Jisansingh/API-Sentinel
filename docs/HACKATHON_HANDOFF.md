# API Sentinel — Hackathon Handoff (CyberCup 6, CC6-IC07)

No credentials in this file. Details and measurements: `docs/PHASE2_REPORT.md`; deployment: `docs/DEPLOYMENT.md`.

## 1. Where things stand

- Branch `jisan` (tracks `origin/jisan`). Last commit: `95009f0` ("Prepare API Sentinel for CyberCup demo").
- **Phase 2 work is uncommitted** in the working tree (modified + new files; see `git status`). Nothing was committed, pushed, stashed or reset. Review `git diff` and decide on commits yourself.
- Backups (outside the repo, no secrets/databases):
  - `/tmp/api-sentinel-backup-20261014-233322` — Phase 1 close-out (volatile `/tmp`).
  - `~/.api-sentinel-backups/phase2-20261015-112752/` — tracked files at `95009f0` before Phase 2.
  - A snapshot of the finished Phase 2 tree is listed at the end of `docs/PHASE2_REPORT.md` §14.
- Tests: `cd backend && python3 -m pytest tests -q` → 230 passed (isolated; set `DATABASE_URL` to a scratch file to be certain).
- The services already running on :8000/:8080 still execute **Phase 1 code**; restart them (§5) to use Phase 2.

## 2. Architecture (changes since Phase 1 in bold)

- `backend/app/main.py` — `create_app(db_path, enable_capture, fp_secret, enable_demo, api_key, **env, spec_dir, ownership, clock**)`; **`app` is built lazily** so importing the module never creates a database; **access-log redaction filter**.
- `config.py` — settings from env; **`SENTINEL_ENV`, `SENTINEL_SPEC_DIR`, `SENTINEL_OWNERSHIP_PATH`; default bind 127.0.0.1; `validate_environment` (production fails closed)**.
- `capture.py` — safe request summaries (no bodies/tokens/headers); keyed-HMAC credential fingerprint.
- `discovery.py` — inventory, OpenAPI comparison; **segment-level path normalization, single list of Sentinel's own routes, generic spec errors, 2 MiB cap**.
- `analysis.py` — pure detectors: scraping (**burst gated on ≥ 5 distinct paths + low-and-slow**), BOLA enumeration, token replay (**requires concurrent multi-IP use**), **confirmed BOLA from ownership context**, explicit-context cases.
- `risk_scoring.py` — unchanged weights/caps; findings now carry `metadata.reasons`.
- **`timeutil.py`** (naive-UTC normalization), **`ownership.py`** (context loader), **`maintenance.py`** (optional retention CLI).
- `storage.py` — SQLite; internal-route rows hidden at read time; UTC-aware alert upsert.
- Routes — `shadow.py` confines `spec_path`; `health.py` checks storage; findings use a clock-anchored live window.
- `backend/benchmark/` — labelled synthetic benchmark; `backend/simulator/` — traffic driver, shop spec, **`ownership.py`**.
- `demo/` — dashboard (`index.html`, `dashboard.css`, `dashboard.js`, no framework) + key-holding localhost proxy `serve.py` (static allowlist of those 3 files, CSP and other security headers, same key/route/CSRF controls as before).

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

## 5. Demo startup (replace `...` with generated values; never commit them)

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

Browser check: open http://127.0.0.1:8080 → Generate sample traffic → Run scan → change an alert's status/note → Save. Expect 2 shadow APIs, a confirmed-BOLA alert (with the ownership file) and a token-replay alert. Stop the backend to see the error states. Keep the proxy on 127.0.0.1.

Benchmark: `cd backend && python3 -m benchmark.run --markdown -` (isolated; never touches your database).

## 6. Restart checklist

1. `git status`, `git rev-parse --short HEAD` (expect `95009f0` plus uncommitted Phase 2 changes unless you commit).
2. Stop the old backend/dashboard processes, then start them as in §5. Existing database rows and the acknowledged `scraping` alert are kept. Historical `/docs` and `/openapi.json` rows stay in the file but no longer appear.
3. `curl http://127.0.0.1:8000/api/health` → `{"status":"ok",...,"database":"ok"}`.
4. If the dashboard shows 401/503, its key differs from the backend's; restart it with the backend's key. Do not disable auth to work around it.
5. Keep `ENABLE_DEMO_TARGET=true` on the demo machine only.

## 7. Known limitations

See `docs/PHASE2_REPORT.md` §12. Highlights: synthetic, self-authored benchmark; slow distributed token abuse and slow ID probing are missed; many users behind one IP can look like one scraper; confirmed BOLA needs ownership data you supply; JSON OpenAPI only; no separate `frontend/` app (not verified as required; the demo dashboard was upgraded instead, see `docs/PHASE2_REPORT.md` §15).
