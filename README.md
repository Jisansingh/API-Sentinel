# API Sentinel

**CyberCup 6.0 Challenge:** CC6-IC07: API Discovery, Security and Abuse Prevention

## Objective

API Sentinel is a security monitoring and discovery platform that identifies, analyzes, and protects APIs from shadow APIs, abuse patterns, and security risks. The system captures API traffic, detects anomalies, discovers undocumented endpoints, and provides risk scoring and alerting.

## Technology Stack

- **Backend:** Python, FastAPI, Pydantic, Uvicorn
- **Database:** SQLite, JSONL
- **Testing:** HTTPX
- **Frontend:** (To be implemented)

## Project Structure

- `backend/` — FastAPI application, discovery, security detection, and storage
- `frontend/` — Web interface (planned)
- `docs/` — Documentation and architecture
- `backend/simulator/` — Traffic simulation and testing tools

## Running the Backend

```bash
cd backend
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Detection API

Sentinel's own routes (including `/api/health`) are never recorded as
traffic. Set `SENTINEL_API_KEY` (>= 32 chars) and send it as
`X-Sentinel-Key`: then every route below needs it. Without a key, reads are
open (local dev only) and the write routes return 503. `/api/health` is
always open.

| Endpoint | Purpose |
|---|---|
| `GET /api/inventory` | Observed endpoints (normalized paths) |
| `GET /api/shadow-apis?spec_path=...` | Observed routes missing from an OpenAPI JSON spec (404/405-only probes excluded) |
| `GET /api/findings` | Current rolling-window findings (read-only) |
| `POST /api/scan` | Run detection and upsert persistent, deduplicated alerts |
| `GET /api/alerts?status=open` | Stored alerts |
| `PATCH /api/alerts/{id}` | Triage: `open`, `acknowledged`, `resolved`, `ignored` (+ `note`) |

Detections: scraping, BOLA enumeration (ID probing with 401/403/404
responses), token replay (one credential from many IPs), plus explicit-context
BOLA. Credentials are identified only by a keyed HMAC fingerprint; set
`SENTINEL_FP_SECRET` (>= 32 chars) to enable it, otherwise the client IP is
the actor.

## Demo (deliberately vulnerable target)

```bash
cd backend
export SENTINEL_FP_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
export SENTINEL_API_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
ENABLE_DEMO_TARGET=true uvicorn app.main:app --port 8000
# second terminal, from backend/, same SENTINEL_API_KEY exported
python3 -m simulator.run
H="X-Sentinel-Key: $SENTINEL_API_KEY"
curl -X POST -H "$H" http://127.0.0.1:8000/api/scan
curl -H "$H" http://127.0.0.1:8000/api/alerts
curl -H "$H" "http://127.0.0.1:8000/api/shadow-apis?spec_path=$PWD/simulator/shop-openapi.json"
```

Dashboard (`demo/`), with auth enabled — run with the same key as the backend:

```bash
# backend started as above (ENABLE_DEMO_TARGET=true); add
#   OPENAPI_SPEC_PATH=$PWD/simulator/shop-openapi.json
# so the shadow-API panel compares against the shop's published spec.
SENTINEL_API_KEY=$SENTINEL_API_KEY BACKEND_URL=http://127.0.0.1:8000 python3 demo/serve.py
# open http://127.0.0.1:8080  (Refresh, Generate sample traffic, Run scan, triage alerts)
# "Generate sample traffic" hits the demo shop; expect shadow API GET /shop/internal/export
```

The proxy adds `X-Sentinel-Key` server-side for Sentinel routes only; the
browser never sees the key. Writes through the proxy must come from the
dashboard's own origin with a JSON body (CSRF protection).

Never set `ENABLE_DEMO_TARGET` outside a demo: the shop API is intentionally
vulnerable to BOLA.

## Next Steps

1. Implement core modules (capture, discovery, abuse detection)
2. Set up API routes for inventory and alerts
3. Configure SQLite storage layer
4. Build risk scoring engine
5. Develop frontend dashboard
