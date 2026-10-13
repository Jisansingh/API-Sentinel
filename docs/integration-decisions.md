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
