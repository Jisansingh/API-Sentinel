# API Sentinel — deployment notes

Local-demo safeguards and production requirements are listed separately on purpose.
**Nothing here is evidence of production readiness**: the system has only been run
as a single process on localhost against synthetic traffic.

## 1. Local demo (default, `SENTINEL_ENV=development`)

| Behaviour | Why it is acceptable only locally |
|---|---|
| Binds `127.0.0.1` by default (`API_HOST`) | Not reachable from other machines. |
| Without `SENTINEL_API_KEY`: reads are open, writes (`/api/scan`, `PATCH /api/alerts/*`) return 503 | Convenience for a laptop demo; a startup warning is logged. |
| Without `SENTINEL_FP_SECRET`: actor = client IP | No credential fingerprints, so no token-replay or per-credential BOLA signals. |
| `ENABLE_DEMO_TARGET=true` mounts the deliberately vulnerable shop | Never expose it. |
| Dashboard proxy (`demo/serve.py`) holds the admin key and binds `127.0.0.1:8080` | Anyone with local access to that port acts with the admin key. |

## 2. Production requirements (`SENTINEL_ENV=production`)

The app **refuses to start** (`ValueError`) unless all of these hold:

- `SENTINEL_API_KEY` set, ≥ 32 characters (then *every* route except `GET /api/health` needs `X-Sentinel-Key`).
- `SENTINEL_FP_SECRET` set, ≥ 32 characters.
- `ENABLE_DEMO_TARGET` off.

Not enforced by code, your responsibility:

- Bind: keep `--host 127.0.0.1` behind a reverse proxy, or firewall the port. The code does not check the bind address.
- TLS terminates at the proxy. The admin key travels in a header, so never send it over plain HTTP across a network.
- `chmod 600` the SQLite file; it holds client IPs, request paths and credential fingerprints (never tokens or bodies).
- Generate secrets with `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`, keep them out of git and shell history, rotate per event/environment. Rotating `SENTINEL_FP_SECRET` changes every fingerprint (old and new credentials will not match).
- Use an absolute `DATABASE_URL` (`sqlite:////var/lib/sentinel/sentinel.db`); the default `sqlite:///./api_sentinel.db` is relative to the working directory.

## 3. Configuration reference

| Variable | Default | Meaning |
|---|---|---|
| `SENTINEL_ENV` | `development` | `production` enforces the checks above. |
| `SENTINEL_API_KEY` | unset | Admin key for Sentinel's own API. |
| `SENTINEL_FP_SECRET` | unset | HMAC key for credential fingerprints. |
| `DATABASE_URL` | `sqlite:///./api_sentinel.db` | SQLite only. |
| `API_HOST` / `API_PORT` | `127.0.0.1` / `8000` | Informational for `Settings`; the real bind is whatever you pass to uvicorn. |
| `ENABLE_CAPTURE` | `true` | Turn traffic capture off. |
| `OPENAPI_SPEC_PATH` | unset | Trusted spec used by `/api/shadow-apis`. Its directory is also the allowed directory for `?spec_path=`. |
| `SENTINEL_SPEC_DIR` | unset | One more directory `?spec_path=` may read from. Without either variable the `spec_path` override is disabled (HTTP 400). Only `.json` files, symlinks resolved. |
| `SENTINEL_OWNERSHIP_PATH` | unset | JSON ownership context for confirmed-BOLA detection (see `backend/app/ownership.py`). Invalid file ⇒ startup error. |
| `ENABLE_DEMO_TARGET` | `false` | Demo shop. |

## 4. Start / stop

```bash
cd backend
python3 -m pip install -r requirements.txt          # add requirements-dev.txt to run tests
export SENTINEL_ENV=production SENTINEL_API_KEY=... SENTINEL_FP_SECRET=...   # from your secret store
export DATABASE_URL=sqlite:////var/lib/sentinel/sentinel.db OPENAPI_SPEC_PATH=/etc/sentinel/openapi.json
python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --proxy-headers --forwarded-allow-ips=127.0.0.1
```

Stop with `SIGTERM` (Ctrl-C locally); uvicorn finishes in-flight requests. SQLite writes are committed per request, so an abrupt stop loses nothing already stored.
`uvicorn app.main:app` builds the app on first attribute access, so merely importing `app.main` no longer creates a database.

## 5. Reverse proxy

Without forwarded headers every client looks like the proxy's IP, which breaks per-client scraping and replay detection. Pass the real IP and tell uvicorn which proxy to trust:

```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header X-Forwarded-For $remote_addr;      # overwrite, do not append client-supplied values
    proxy_set_header Host $host;
}
```

Run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy ip>` (never `*` on an exposed port: clients could forge their own IP).
Sentinel analyses traffic that **passes through the app it is mounted on**; it does not sniff a network.

## 6. Health and troubleshooting

- `GET /api/health` (no key): `200 {"status":"ok","database":"ok"}`; `503 {"status":"degraded","database":"unavailable"}` if the SQLite file is missing, unreadable or lacks tables. The probe never creates the file.
- `401 missing or invalid X-Sentinel-Key`: key mismatch, or the dashboard proxy was started with a different `SENTINEL_API_KEY` than the backend.
- `503 ... write endpoints are disabled`: no `SENTINEL_API_KEY` in a development run.
- `400 spec_path must be a .json file inside an allowed specification directory`: set `OPENAPI_SPEC_PATH` or `SENTINEL_SPEC_DIR`, or omit `spec_path`.
- App exits at startup with `insecure production configuration`: see §2.
- Everything attributed to one IP: reverse-proxy headers (§5).
- Dashboard "Findings" empty but alerts exist: findings are a live one-minute view; alerts come from `Run scan`.

## 7. Retention (optional, never automatic)

Nothing is deleted unless you run this. Dry run is the default:

```bash
python3 -m app.maintenance --db /var/lib/sentinel/sentinel.db --captures-days 30 --alerts-days 90
python3 -m app.maintenance --db ... --captures-days 30 --alerts-days 90 --apply --backup-to /safe/place/pre-prune.db
```

Only captured requests older than `--captures-days` and `resolved`/`ignored` alerts older than `--alerts-days` are removed; `open`/`acknowledged` alerts are never pruned. `--backup-to` takes a consistent copy first and refuses to overwrite an existing file. Stop or quiesce traffic for very large prunes (SQLite takes a write lock).

## 8. OpenAPI validation

JSON OpenAPI/Swagger files only (≤ 2 MiB). A file is accepted when it parses and has a `paths` object; operations are the HTTP-method keys under each path. Not supported: YAML, `$ref`-split files, `servers`/`basePath` prefixes. Invalid input yields `spec_loaded=false` with a generic reason (no paths or content echoed) and every observed route is listed as "documentation status unknown".
