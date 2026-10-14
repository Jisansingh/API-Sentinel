# API Sentinel — Hackathon Handoff (CyberCup 6)

Final backup/close-out note. No feature work. No credentials in this file.

## 1. Where things stand

- Branch: `jisan` tracking `origin/jisan`. HEAD at handoff: `d1cee82` ("Simplify API Sentinel backend pipeline").
- Working tree has uncommitted work (19 modified tracked files + 15 untracked source files). Nothing was committed, pushed, reset, or cleaned during close-out.
- Backup (outside repo, verified): `/tmp/api-sentinel-backup-20261014-233322`
  - `tracked.diff` + `diffstat.txt` (all tracked modifications)
  - `untracked/` (new sources: `backend/app/auth.py`, `backend/app/routes/demo_shop.py`, `backend/simulator/*`, 8 new test files incl. `conftest.py`, `demo/index.html`, `demo/serve.py`)
  - `HEAD.txt`, `BRANCH.txt`, `STATUS.txt`, `LOG.txt`
  - Excludes secrets, `*.db`, `*.log`, caches (`__pycache__`, `.pytest_cache`).

## 2. Architecture

- `backend/app/main.py` — FastAPI factory `create_app(db_path, enable_capture, fp_secret, enable_demo, api_key)`. Mounts health (open), inventory, shadow-apis, findings, alerts, and the demo shop only when enabled. SQLite file ensured via `init_db`.
- `backend/app/config.py` — `Settings.from_env()`: `DATABASE_URL`, `API_HOST/PORT`, `ENABLE_CAPTURE`, `OPENAPI_SPEC_PATH`, `SENTINEL_FP_SECRET` / `SENTINEL_API_KEY` (both `SecretStr`, min 32 chars), `ENABLE_DEMO_TARGET` (default false).
- `backend/app/capture.py` — `RequestCaptureMiddleware` stores safe summaries only (method, sanitized path, status, duration, client IP, `actor_fp` HMAC, timestamp). Never stores bodies, tokens, or headers. Skips Sentinel's own routes; `/api/health` is not captured.
- `backend/app/discovery.py` — inventory builder + OpenAPI spec comparison; 404/405-only probes excluded from shadow APIs.
- `backend/app/analysis.py` — pure pipeline (no FastAPI imports): scraping from captures, BOLA enumeration, token replay, explicit-context cases.
- `backend/app/risk_scoring.py` — `RiskScorer` + `escalate()` (magnitude + context bonuses, capped at 100; breakdowns sum to score).
- `backend/app/storage.py` — SQLite: `captured_requests` (+ additive `actor_fp` column) and `alerts` table keyed `(detection_type, actor, endpoint)`.
- Routes: `routes/health.py` (`GET /api/health`, always open), `routes/inventory.py`, `routes/shadow.py`, `routes/findings.py` (read-only rolling window), `routes/alerts.py` (`POST /api/scan` only writer, `GET /api/alerts`, `PATCH /api/alerts/{id}`), `routes/demo_shop.py` (vulnerable target, demo only).
- `backend/simulator/` — `run.py` (stdlib traffic driver) + `shop-openapi.json` (published spec).
- `demo/` — `serve.py` (stdlib proxy + static page) + `index.html` (dashboard with Refresh, Generate sample traffic, Run scan, alert triage).

## 3. Implemented detections

- Scraping: >10 requests / >20 distinct paths per actor in 60 s rolling window (configurable); reported endpoint is actor's most frequent normalized path.
- BOLA enumeration (capture-based): per (actor, method, ID template), rolling 300 s: >10 distinct IDs with >=50% 401/403/404. Attempt signal; confirmed ownership checks need explicit context.
- Token replay: one credential fingerprint from >3 distinct IPs in 3600 s. Fingerprint is keyed HMAC-SHA256 (first 32 hex shown); raw tokens never stored or returned.
- Explicit-context BOLA / token-replay cases: caller-supplied context only; no context yields no findings (no guessing from traffic).
- Shadow APIs: observed routes missing from OpenAPI spec; routes that only ever 404/405 are excluded. Missing/invalid spec returns `spec_loaded=false` with all observed routes flagged "documentation status unknown".
- Risk escalation: base weight + magnitude (>=3x +10, >=6x +20, >=12x +30) + context (+10 write method, +10 sensitive path segment), capped at 100.

## 4. Authentication

- Sentinel API key: `SENTINEL_API_KEY` (>=32 chars), sent as `X-Sentinel-Key`, constant-time compare (`backend/app/auth.py`).
  - Key set: every Sentinel route except `GET /api/health` requires it; wrong/missing yields `401`. Verified: `POST /api/scan` without key returns `401 {"detail":"missing or invalid X-Sentinel-Key"}` and executes nothing (auth dependency runs before scan logic).
  - Key unset (local dev only): reads open with startup warning; writes (`POST /api/scan`, `PATCH /api/alerts/{id}`) return `503`.
  - Short key at startup raises `ValueError` (fail loudly, never silently open).
- Credential fingerprinting: `SENTINEL_FP_SECRET` (>=32 chars). Set enables `actor_fp`; unset/short disables it and client IP is the actor (with a startup warning that never logs the value).
- Dashboard proxy (`demo/serve.py`): reads `SENTINEL_API_KEY` from its own environment and adds it server-side only to allowlisted routes (GET inventory/findings/shadow-apis/alerts, POST /api/scan, PATCH /api/alerts/{id}). Browser never sees the key. Writes additionally require dashboard `Origin`, `Content-Type: application/json`, body <=4 KiB, and localhost `Host`.

## 5. Demo workflow

1. Backend with demo target + spec path (from `backend/`).
2. Traffic: either `python3 -m simulator.run` (from `backend/`, normal + shadow + scraping + BOLA + token replay) or dashboard "Generate sample traffic" (replays embedded plan; expect shadow `GET /shop/internal/export`).
3. `POST /api/scan` (or dashboard "Run scan"), then `GET /api/alerts`, triage via `PATCH /api/alerts/{id}`.
4. Shadow check: `GET /api/shadow-apis?spec_path=<abs path to simulator/shop-openapi.json>`.

## 6. Exact startup commands (placeholders, no real secrets)

Backend (from `backend/`, binds `127.0.0.1:8000`):

```bash
cd backend
export SENTINEL_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export SENTINEL_FP_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
ENABLE_DEMO_TARGET=true OPENAPI_SPEC_PATH="$PWD/simulator/shop-openapi.json" \
  python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Dashboard (from repo root, same key as backend, binds `127.0.0.1:8080`):

```bash
SENTINEL_API_KEY="$SENTINEL_API_KEY" BACKEND_URL=http://127.0.0.1:8000 python3 demo/serve.py
# open http://127.0.0.1:8080
```

Never set `ENABLE_DEMO_TARGET` outside the demo: the shop is intentionally vulnerable to BOLA.

## 7. Test results

- Fresh full suite at close-out (isolated: every test uses `tmp_path` SQLite files + in-process `TestClient`; run with demo env vars unset so no contamination): **134 passed in ~6.5 s** (`python3 -m pytest tests -q` from `backend/`).
- Matches the previous reported result of 134 passed. No fresh run was skipped; the suite does not touch `./api_sentinel.db` or the running services.

## 8. Known limitations

- Alerts only capture what a scan observed; a burst that leaves the rolling window before any scan is missed (`unchanged` vs `occurrences+1` dedup by `(detection_type, actor, endpoint)`; `resolved` reopens on new evidence; `ignored`/`acknowledged` suppress).
- Capture-based BOLA is an enumeration-attempt signal; confirmed exploitation needs explicit ownership context.
- OpenAPI comparison is JSON-only; YAML specs unsupported.
- Behind a proxy, run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy>` or all clients look like one IP.
- No alert retention/archiving yet. Dashboard proxy binds `127.0.0.1` only — anyone with local port access acts with the admin key; do not expose it.

## 9. Service status at handoff (read-only checks, no writes)

- Backend `127.0.0.1:8000` listening; `GET /api/health` (no auth) → `200 {"status":"ok"}`.
- `backend/simulator/shop-openapi.json` present (used as `OPENAPI_SPEC_PATH`).
- Dashboard `127.0.0.1:8080` listening; `GET /` → `200` HTML.
- Via dashboard proxy (key added server-side, none sent by client): `GET /api/inventory` → 200, `GET /api/findings` → 200, `GET /api/alerts` → 200, `GET /api/shadow-apis?spec_path=...` → 200.
- No traffic generated, no scans run, no alert statuses changed, no DB reset, no restarts during verification.

## 10. Tomorrow's restart steps

1. Confirm repo state: `git status`, `git rev-parse HEAD` (expect `d1cee82` unless you intentionally commit).
2. The `/tmp` secrets file and `/tmp` backup may not survive a reboot. If the demo env file is gone, regenerate both secrets per §6 (never reuse across events; never commit them).
3. Start the backend first (§6), confirm `GET http://127.0.0.1:8000/api/health` → 200 and shop routes appear in `/openapi.json`.
4. Start the dashboard with the same key (§6), open `http://127.0.0.1:8080`, use Refresh / Generate sample traffic / Run scan.
5. If the dashboard shows 401/503 on protected routes, the dashboard key does not match the backend key — restart the dashboard with the backend's key (do not disable auth to work around it).
6. Keep `ENABLE_DEMO_TARGET=true` only on the demo machine. Do not push, commit, or stash during the event unless you mean to.
