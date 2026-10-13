# API Sentinel — Backend Integration Contract

Owner: backend integration + security pipeline. Discovery side implemented by the
BACKEND API DISCOVERY agent; abuse detection and risk scoring are implemented
separately by Claude. This document is the shared contract both sides follow.

## 1. Inventory response schema — `GET /api/inventory`

Aggregates sanitized capture records by `(method, normalized path)`.
Empty inventory returns HTTP 200 with `"items": []` (never an error).

```json
{
  "items": [
    {
      "method": "GET",
      "path": "/api/users/{id}",
      "request_count": 2,
      "status_codes": [200],
      "last_status": 200,
      "last_seen": "2026-10-14 00:00:00",
      "query_params": ["next", "token"]
    }
  ],
  "total_requests": 5,
  "total_endpoints": 3
}
```

Field notes:

- `path` is the **normalized** path (`/users/101` → `/users/{id}`).
- `query_params` lists safely observed query-parameter **names only**, never values.
- Raw IDs visible in stored paths (e.g. `/users/101`) are resource identifiers, not
  secrets; sensitive query **values** are already redacted at capture time.

## 2. Shadow API response schema — `GET /api/shadow-apis`

Compares observed `(method, path)` pairs against a local OpenAPI JSON file.

- Default spec file comes from the `OPENAPI_SPEC_PATH` environment variable
  (`Settings.openapi_spec_path`, default `null`).
- `GET /api/shadow-apis?spec_path=/path/to/openapi.json` overrides it per request.
- Only local JSON files are supported. OpenAPI path templates (`/users/{id}`,
  including other placeholder names like `/users/{userId}`) match normalized
  observed paths.

```json
{
  "documented": [{ "method": "GET", "path": "/api/health" }],
  "shadow_apis": [
    {
      "method": "GET",
      "path": "/api/admin/export",
      "request_count": 4,
      "last_seen": "2026-10-14 00:00:00",
      "reason": "observed in captured traffic but not documented in the OpenAPI specification"
    }
  ],
  "spec_loaded": true,
  "spec_error": null
}
```

Missing/invalid specification is handled gracefully: HTTP 200 with
`"spec_loaded": false`, a human-readable `"spec_error"`, `"documented": []`,
and every observed route listed under `"shadow_apis"` with a reason stating
that documentation status is unknown (NOT silently dropped, NOT a 500).

## 3. Captured-event fields available to other modules

`storage.fetch_captured_requests(db_path)` returns one dict per request
(oldest first). This is the shared read interface for abuse detection and
risk scoring — no schema change needed to consume it:

| Field         | Example               | Notes                                              |
| ------------- | --------------------- | -------------------------------------------------- |
| `method`      | `"GET"`               | Uppercase HTTP method                              |
| `path`        | `"/api/u?token=%5B…"` | Sanitized; sensitive query values already redacted |
| `status_code` | `200`                 | Response status                                    |
| `duration_ms` | `1.23`                | Server-side handling time                          |
| `client_ip`   | `"testclient"`        | Direct peer only; may be a proxy, not the end user |
| `created_at`  | `"2026-10-14 …"`      | UTC, lexicographically sortable                    |

Guaranteed ABSENT (never collected, never stored): request/response bodies,
raw tokens, passwords, API keys, cookies, `Authorization` headers. Detector
modules must not expect these fields to exist.

Discovery helpers in `app/discovery.py` are also reusable:
`normalize_path()`, `extract_query_param_names()`, `build_inventory()`,
`load_openapi_spec()`, `find_shadow_apis()`.

## 4. Proposed interface for submitting detection results (DRAFT)

Claude's detector modules own their logic (BOLA, scraping, token replay, risk
scoring — explicitly out of scope for discovery). To keep the pipeline
consistent, new findings SHOULD be reported in this shape (Pydantic draft:
`schemas.DetectionResultIn`; no endpoint consumes it yet):

```json
{
  "detector": "abuse-detection",
  "method": "POST",
  "path": "/api/login",
  "finding_type": "rate-anomaly",
  "severity": "medium",
  "reason": "120 requests/min from one client",
  "confidence": 0.5
}
```

- `severity` is one of `low | medium | high | critical`.
- `confidence` is `0.0–1.0`.
- `path` SHOULD use the same normalization (`/users/{id}`) so findings join
  cleanly with inventory rows.
- Proposed (not yet implemented): `POST /api/findings` accepting a list of the
  above; `GET /api/findings` for the dashboard. Integrator to confirm.

## 5. Module boundaries (do not duplicate)

- Discovery (this agent): `app/discovery.py`, `app/routes/inventory.py`,
  `app/routes/shadow.py`, inventory/shadow schemas, this contract.
- Claude: `app/abuse_detection.py`, `app/risk_scoring.py`,
  `app/routes/alerts.py`, `app/routes/analytics.py`,
  `app/shadow_detection.py` (left empty — reserved for behavioral shadow-IP/
  anomaly work, distinct from spec-comparison shadow APIs).
- Shared (changed only with backward compatibility): `app/storage.py` (added
  read-only `fetch_captured_requests`; table schema untouched),
  `app/schemas.py` (additive models only; `HealthResponse`/`CapturedRequest`
  unchanged), `app/config.py` (added optional `openapi_spec_path`),
  `app/main.py` (router registration + `app.state.db_path`).

## 6. Unresolved integration decisions

1. `POST /api/findings` + `GET /api/findings`: confirm endpoint names and
    whether findings persist in SQLite or stay in memory.
2. Severity vocabulary: is `low | medium | high | critical` acceptable, or does
    risk scoring need numeric bands?
3. Should inventory exclude our own monitoring routes (`/api/health`) or keep
    them flagged as documented-only?
4. Risk-score attachment: does risk scoring annotate inventory items in place,
    or return a separate keyed map?
5. OpenAPI YAML support: currently JSON only — needed for CyberCup judging?
