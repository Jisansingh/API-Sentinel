# Abuse rules, endpoint risk and alert investigation (Phase 5)

Code: `backend/app/analysis.py` (rules), `app/endpoint_risk.py` (scores), `app/investigation.py`
(alert detail), `app/storage.py` (incidents, score snapshots). Tests: `tests/test_phase5_*.py`.

## Rules

Every finding carries `metadata.rule_id`; `analysis.RULES` holds each rule's explanation and the
thresholds below. Alert dedup is unchanged: one alert per (detection type, caller, endpoint).

| Rule | Type | Fires when | Not flagged |
|---|---|---|---|
| REPLAY-CONCURRENT | token_replay | one credential fingerprint from > 3 IPs in 1 h, switching IP within 60 s | roaming minutes apart, retries from one IP, anonymous traffic |
| SCRAPE-BURST / -SLOW / -ROTATION | scraping | > 10 req over ≥ 5 paths or > 20 paths in 60 s; > 100 req over ≥ 20 paths in 1 h; one IP rotating ≥ 10 credentials | pagination of one path (query values are not new objects), polling a few paths |
| BOLA-ENUM | bola_enumeration | > 10 distinct IDs on one route in 5 min, ≥ 50 % 401/403/404 | (attempt only, never "confirmed") |
| BOLA-ENUM-SLOW | bola_enumeration | same thresholds over 1 h (paced below the 5 min window) | (attempt only) |
| BOLA-CONFIRMED | bola | mapped user gets 2xx **with content** for another user's object | own objects, unmapped callers/objects |
| BOLA-BLOCKED | bola_blocked | same, answered 401/403/404 | — never reported as a vulnerability |
| BOLA-INCONCLUSIVE | bola_inconclusive | same, answered 204/3xx/5xx/other 4xx | — disclosure not shown either way |
| AUTH-FAILURES | access_denied | ≥ 10 401/403 for one caller in 5 min, ≥ 50 % of its requests | denials already explained by a BOLA-ENUM alert |
| ANOMALY-RATE / -CALLER-RATE | rate_anomaly | current hour > max(3×median, median+3·1.4826·MAD, 5) of the same weekday/hour in ≥ 3 earlier weeks | recurring peaks; no history = silent |
| ANOMALY-ERRORS | error_spike | ≥ 10 req and ≥ 50 % 5xx in 5 min; previous 7 days (≥ 20 req) < 10 % 5xx | no history |
| ANOMALY-PAYLOAD | payload_anomaly | request body > max(1024 B, 4 × p95 of previous 7 days, ≥ 20 req) | no history |

Ownership context (for BOLA-CONFIRMED/BLOCKED/INCONCLUSIVE) comes from `SENTINEL_OWNERSHIP_PATH`; with
the demo shop enabled, the synthetic demo users/orders are added automatically (keyed fingerprints,
never raw tokens). `GET /shop/secure/orders/{id}` is the demo's fixed route (403 for other users' orders).

Alert scores keep the existing scale: base weight (BOLA 35, scraping 30, token replay 35, access
denials 25, anomalies 20, BOLA attempts 15) + magnitude (+10/+20/+30) + context (+10 write, +10
sensitive segment), capped at 100.

## Endpoint risk score (`GET /api/risk/endpoints`)

| Factor | Max | Points |
|---|---|---|
| exposure | 20 | shadow (undocumented) 15; API gateway disabled 5 |
| authentication | 20 | a 2xx served without any credential 20; otherwise HTTP Basic seen 5 |
| data_sensitivity | 20 | name-based high 15 / medium 8; write method 5; admin/internal/export/debug 5 |
| behavior | 15 | active anomaly alerts: 10 + 5 per further type |
| security_events | 25 | confirmed BOLA 25; else active abuse alerts 10 + 5 per further type (max 20) |

Not scored: Sentinel's own routes (never in the inventory) and routes that only ever answered 404/405
(no endpoint was served). The latter are returned in `excluded` with the reason, so
`scored + excluded = discovered` (`coverage`); the inventory marks them `confirmed_live: false`.
Every score has `confidence`: `provisional` with fewer than 20 captured requests or a missing input
(spec, authentication, baseline history), else `established`; `confidence_reason` says which.
Bands: 0 none, 1–39 low, 40–69 medium, 70–100 high. Only open/acknowledged alerts count, each in one
factor, once per detection type, so repeated scans and refreshes cannot inflate a score. Unknown
inputs (no spec, auth type not recorded, < 20 requests of history, public reachability) add 0 and
are listed under `unavailable_inputs`.

Example (demo run): `GET /shop/admin/stats` = exposure 20 (shadow 15 + gateway off 5) +
data_sensitivity 5 (admin segment) + security_events 10 (one active access_denied alert) = **35, low**.

History: `POST /api/scan` and alert triage store a snapshot for an endpoint only when its score or
factor contributions changed. `change` compares the current values with the latest snapshot (or the
latest two snapshots) and names the factors and alert ids responsible; before any genuine earlier
snapshot exists it is `null` with "unavailable". Nothing is reconstructed after the fact.

## Investigation

- `GET /api/alerts/{id}`: rule (id, title, explanation), category, severity band, outcome,
  disposition (status, note), the captured requests behind the alert (≤ 50, sensitive query values
  redacted, credential shown as a fingerprint prefix), enforcement, incident and related alerts,
  provenance and missing fields. Evidence is redacted again (credential keys, bearer/basic values,
  e-mail addresses).
- Request evidence for BOLA outcome alerts is filtered by outcome: confirmed = 2xx except 204,
  blocked = 401/403/404, inconclusive = anything else; when the stored `object_ids` list is complete
  (it is capped at 20) the object id must match too. Probing 404s stay with the enumeration alert.
- `related_by_caller`: other alerts sharing the credential fingerprint or a client IP within the
  incident gap, across categories (read-only; nothing is regrouped). `possible_duplicate` marks the
  same type and endpoint, e.g. a legacy IP-keyed scraping alert next to the credential-keyed one
  recorded by current code. Alerts without a rule id are `legacy`. Duplicates are left for analyst
  triage; Sentinel never changes their status.
- Incident ids are displayed as `INC-n` because they are numbered separately from alert ids.
- Enforcement is `blocked` / `rate_limited` only when the access-control log (`gateway_events`)
  recorded that decision for the alert's client IP in its time span; otherwise `flagged_only`.
- `GET /api/incidents`: alerts grouped by category + caller (+ endpoint for endpoint-wide anomalies),
  with no gap over 1 h. Ids are stored (`alerts.incident_id`), so they are stable; alerts keep their
  own ids, evidence and status. Older alerts are grouped once on upgrade.
- Dashboard: Threat Detection → filters (status, type, severity, last seen, endpoint/caller) →
  **Investigate** → panel with all of the above → "View endpoint risk explanation" opens the
  endpoint's factor breakdown on Risk & Analytics.

## Limitations

- Sensitivity is inferred from route/parameter names (e.g. `/orders` scores low); response bodies
  and sizes are never captured.
- Enforcement matching uses client IPs; a credential-only caller without a recorded IP shows
  `flagged_only` with a note.
- Anomaly rules need weeks (rate) or ≥ 20 requests (errors/payload) of history; benchmark traffic
  has none, so the benchmark does not measure them.
- Holdout recall is unchanged at 33.3 %: the new rules were not tuned on the holdout set.
- Shadow APIs: `deprecated_apis` lists documented operations marked `deprecated: true` that still
  receive traffic; `unmanaged_apis` stays empty with `unmanaged_note`, because "unmanaged" needs an
  API ownership/management registry that Sentinel does not have.
- Runtime baselines report `baseline_state` per endpoint/caller: `no_baseline` (no earlier
  matching weekday/hour), `insufficient` (fewer than 3), `ready`, or `deviation` (above threshold).
- Inventory `sensitivity_basis` names the route/parameter terms behind the sensitivity guess.

## Persistent traffic history and adaptive baselines (`GET /api/runtime/history`)

Every captured request also updates one hourly row per (method, normalized endpoint) in
`traffic_history`, in the same SQLite transaction: request count, status classes, response size from
the response `Content-Length` (`response_sized` counts how many had one) and distinct callers (keyed
credential fingerprint, else client IP). No headers, tokens, bodies or query values. Sentinel's own
routes are skipped. On first start, existing captures are backfilled once (marked in `schema_meta`);
response sizes are unknown for them. Retention: `python -m app.maintenance --db ... --history-days N`.

| State | Evidence |
|---|---|
| `no_baseline` | no earlier hour of traffic for the endpoint |
| `insufficient` | history exists but not yet: traffic on 3 UTC days, 48 h between first and last observation, 6 active hours (quarantined hours excluded) |
| `ready` | a trusted baseline exists and the current hour is within it |
| `deviation` | the current hour exceeds the threshold (max(3 x median, median + 3 x 1.4826 x MAD, 5); same hour of day once that hour was seen on 3 days), or 5xx share >= max(50 %, baseline + 30 points) on >= 10 requests, or the largest response > 4 x the baseline p95 |

Poisoning protection: hours that overlap an alert on the endpoint (unless the alert was marked
`ignored`) or exceeded the trusted baseline are quarantined and never learned. `POST /api/scan`
stores a new trusted baseline only when the evidence is met; otherwise the last trusted one is kept
(and shown, with its learning time). Reads never write. Confidence: `none` without a baseline,
`high` with >= 7 days and a same-hour-of-day profile, else `moderate`. Limitation: a genuine, lasting
increase in traffic is quarantined as "exceeded the trusted baseline" until an operator acts; it is not
learned automatically. Only active hours are stored, so the median is per active hour.
