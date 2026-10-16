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
| `SENTINEL_RATE_LIMITS_PATH` | unset | JSON per-endpoint limits and window; unset ⇒ built-in per-endpoint defaults, 60 s window. Unknown endpoint ⇒ startup error. |
| `SENTINEL_PRINCIPALS_PATH` | unset | JSON principals (credential fingerprints → `user`/`vp`); needs `SENTINEL_FP_SECRET`. Unset ⇒ nobody gets the VP quota. |
| `SENTINEL_GATEWAY_CONFIG` | unset | JSON upstream + route allowlist; enables `/gateway/*`. |
| `SENTINEL_EVALUATION_PATH` | `evaluation-latest.json` next to the database file | Latest successful evaluation result (see §9). Must not be the database file itself. |

Rate limiting, the VP quota and the gateway are described in `docs/GATEWAY_AND_RATE_LIMITS.md`, including the
deployment controls code cannot enforce (no direct path to the upstream, TLS, one process per instance).

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
Uvicorn's default trusts `X-Forwarded-For` from 127.0.0.1, so any **local** client can choose the IP that rate limits
and detection see. If clients connect to uvicorn directly, start it with `--no-proxy-headers`.
Sentinel analyses traffic that **passes through the app it is mounted on**; it does not sniff a network.

## 6. Health and troubleshooting

- `GET /api/health` (no key): `200 {"status":"ok","database":"ok"}`; `503 {"status":"degraded","database":"unavailable"}` if the SQLite file is missing, unreadable or lacks tables. The probe never creates the file.
- `401 missing or invalid X-Sentinel-Key`: key mismatch, or the dashboard proxy was started with a different `SENTINEL_API_KEY` than the backend.
- `503 ... write endpoints are disabled`: no `SENTINEL_API_KEY` in a development run.
- `400 spec_path must be a .json file inside an allowed specification directory`: set `OPENAPI_SPEC_PATH` or `SENTINEL_SPEC_DIR`, or omit `spec_path`.
- App exits at startup with `insecure production configuration`: see §2.
- Everything attributed to one IP: reverse-proxy headers (§5).
- Dashboard shows **Version mismatch**, or Access control shows 404/401: the backend or `demo/serve.py` was started
  from older code than the page. Restart it from the updated source (`scripts/run-local.sh`, see
  `docs/GATEWAY_AND_RATE_LIMITS.md` §8). `GET /api/health` → `api_revision` tells you which backend you reach.
- "The demo shop is not mounted on this backend": the backend was started without `ENABLE_DEMO_TARGET=true`
  (development only). `scripts/run-local.sh status` shows "demo shop NOT mounted".
- Dashboard "Findings" empty but alerts exist: findings are a live one-minute view; alerts come from `Run scan`.

## 7. Retention (optional, never automatic)

Nothing is deleted unless you run this. Dry run is the default:

```bash
python3 -m app.maintenance --db /var/lib/sentinel/sentinel.db --captures-days 30 --alerts-days 90
python3 -m app.maintenance --db ... --captures-days 30 --alerts-days 90 --apply --backup-to /safe/place/pre-prune.db
```

Only captured requests older than `--captures-days` and `resolved`/`ignored` alerts older than `--alerts-days` are removed; `open`/`acknowledged` alerts are never pruned. `--backup-to` takes a consistent copy first and refuses to overwrite an existing file. Stop or quiesce traffic for very large prunes (SQLite takes a write lock).

## 8. OpenAPI validation

JSON OpenAPI/Swagger files (≤ 2 MiB), and YAML when PyYAML is installed (it is in `requirements.txt`; `scripts/run-local.sh status` reports it). A file is accepted when it parses and has a `paths` object; operations are the HTTP-method keys under each path. Not supported: `$ref`-split files, `servers`/`basePath` prefixes. Invalid input yields `spec_loaded=false` with a generic reason (no paths or content echoed) and every observed route is listed as "documentation status unknown".

## 9. Evaluation results

`POST /api/evaluation` (admin key, at most 3 per minute, one at a time — a concurrent run gets 409) runs the
labelled benchmark (`backend/benchmark/`) in an isolated subprocess with its own temporary database. Only
when that run completes and its output validates is the result written, atomically and with mode 600, to
`SENTINEL_EVALUATION_PATH` (default: `evaluation-latest.json` in the same directory as the SQLite file).
`GET /api/evaluation` reads that file, so the latest result survives restarts; a failed, timed-out or
malformed run leaves it unchanged. The file holds synthetic-benchmark metrics only (no credentials,
traffic, alerts or request bodies) and is never the security database.

- Clear results intentionally: delete that file (the dashboard then shows "not run yet").
- Missing, empty, malformed or unreadable file: `GET` returns `available: false` with a note saying which;
  nothing is guessed. Run a new evaluation to replace it.
- With `DATABASE_URL` pointing at `:memory:` there is no durable location; results last until restart and
  the response says `persisted: false`.

## 10. Main instance and lab instances

`scripts/run-local.sh start|status|stop <env-file>` runs one backend + dashboard pair per env file. Keep
one env file (mode 600, outside the repository) per instance, each with its own `DATABASE_URL`,
ports and secrets; the run directory is `<env-file>.run/`.

- Main: `~/.api-sentinel/live.env` (8000/8080), no `SENTINEL_GATEWAY_CONFIG`, so no gateway.
- Shadow lab: `~/.api-sentinel/shadow-lab.env` (9301/9302), its own database, and a gateway config
  with `allow_private_network: true` because its upstream is the local lab on 9000. Setting
  `SENTINEL_GATEWAY_CONFIG` is the only way the gateway is enabled.
- `run-local.sh stop` only stops PIDs started from the same checkout as the script.
- Status/diagnostics: `run-local.sh status <env-file>`, `GET /api/health` (open), and the dashboard's
  Access & Configuration → Diagnostics panel. Tests: `cd backend && .venv/bin/python -m pytest tests -q`
  (create the venv with `python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt`).
