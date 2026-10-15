# API Sentinel — Phase 2 report

Branch `jisan`, base `95009f0`. All changes are **uncommitted** in the working tree (no commit, push, stash or reset was run).
Everything below was measured in this working tree; where something was not run, it says so.

## 1. Outcome in one paragraph

Phase 1 behaviour is preserved (the original 134 tests still pass; a handful were *edited* for deliberate behaviour changes, listed in §9). Phase 2 adds spec-path confinement, fail-closed production mode, UTC normalization, internal-route hiding, ownership-based confirmed-BOLA, a gated scraping rule plus a low-and-slow rule, concurrency-based token-replay evidence, optional retention, and a labelled synthetic benchmark. On the benchmark the tuned build is much better **on the scenarios it was tuned on** and **no better on a holdout set written afterwards**, which still contains several known misses (§6.3). Nothing here shows real-world accuracy.

## 2. Safety and preservation

- A second snapshot of the finished working tree (tracked + new files, no databases/secrets/caches) is recorded in §14.
- Verified before editing: root = this worktree, branch `jisan`, HEAD `95009f0`, clean tree, tracks `origin/jisan`.
- New backup: `~/.api-sentinel-backups/phase2-20261015-112752/` → `tracked-files.tar` (51 tracked files; no databases, logs, caches or secrets), `HEAD.txt`, `STATUS.txt`. The earlier `/tmp/api-sentinel-backup-20261014-233322` was left untouched. Untracked/new Phase 2 files are not in that backup by design (they did not exist yet).
- Live data: the live `backend/api_sentinel.db` (modification time 10:27:33, 28 672 bytes) was never opened by code I ran; I inspected a *copy* to confirm the historical `/docs` and `/openapi.json` rows. The existing acknowledged `scraping` alert and all historical rows are untouched. The live backend (:8000) and dashboard (:8080) were not restarted or reconfigured; they are still running the **old code** and need a restart to pick Phase 2 up (restart steps: `HACKATHON_HANDOFF.md` §6).
- The test suite has a session guard (`tests/conftest.py`) that fails the run if `./api_sentinel.db` is created or modified.

## 3. Phase 1 defects re-verified against the code

| Audit finding | Verified? | Action |
|---|---|---|
| `?spec_path=` reads any server-local file; error echoes the path | Yes (`routes/shadow.py`, `discovery.load_openapi_spec`) | Fixed (§4) |
| `API_HOST` default `0.0.0.0` | Yes (`config.py`) | Default `127.0.0.1` |
| Importing `app.main` creates `./api_sentinel.db` (`app = create_app()` at import) | Yes | Lazy `app` (module `__getattr__`) |
| ISO-string timestamp comparison in `upsert_alerts` | Yes; naive vs offset strings compare wrongly | Parsed UTC comparison, canonical naive-UTC storage |
| `/docs`, `/openapi.json` listed as shadow APIs | Yes: 1 row each in the live DB (copy); baseline benchmark reproduces both false positives | Read-time hiding (§7) |
| Empty `shadow_detection.py`, `routes/analytics.py` | Yes (0 bytes, unreferenced code; mentioned in two docs) | **Not deleted**; left for you to decide |
| Stale `HACKATHON_HANDOFF.md` | Yes | Rewritten |
| Pinned `requirements.txt` did not match the tested environment (fastapi 0.104 vs 0.139) and listed unused packages | Yes | Updated, see §8 |

Further defects found while testing (all fixed, with tests): `urlsplit("//users/5")` treated `users` as a hostname and silently dropped a path segment; `\d` in the ID regex matched non-ASCII digits; a rate-only rule flagged a client polling one endpoint as "scraping".

## 4. Security hardening

| Change | Where | Regression tests (`tests/test_phase2_security.py` unless noted) |
|---|---|---|
| `spec_path` must be a `.json` file *inside* an allowed directory (dir of `OPENAPI_SPEC_PATH`, `SENTINEL_SPEC_DIR`, or `create_app(spec_dir=)`); paths resolved so `..` and symlinks cannot escape; otherwise HTTP 400 with a generic message | `routes/shadow.py:resolve_spec_path` | positive: inside dir, configured dir; negative (parametrized): traversal, absolute, `/etc/passwd`, symlink escape, wrong extension, override disabled |
| Spec errors contain no path or file content; 2 MiB cap | `discovery.load_openapi_spec` | missing / invalid / oversized, asserts no path or content in the response |
| `SENTINEL_ENV=production` refuses to start without API key, fingerprint secret, or with the demo shop on | `config.validate_environment`, `main.create_app` | each missing item, bad env value, and a valid production app that still demands the key; development still boots (writes 503) |
| Loopback default bind | `config.py` | `test_default_bind_is_loopback` |
| Importing the module never opens a database | `main.__getattr__` | subprocess test: no file after `import app.main`; file appears only on `m.app` |
| `/api/health` also checks storage (503 `degraded`, no paths, never creates the file) | `routes/health.py` | `test_health_reports_database_state_without_creating_it` |
| uvicorn access-log lines have secret query values redacted | `main.RedactQueryFilter` | filter unit test + installed-once test; E2E run (§10) showed `token=%5BREDACTED%5D` in the log |
| Writes still require the key; the dashboard proxy still holds the key server-side | unchanged | existing `test_auth.py`, `test_demo_proxy.py` (pass) |

Deliberate development-mode exceptions (documented in `docs/DEPLOYMENT.md`): open reads without a key, IP-as-actor without a fingerprint secret, the demo shop, the key-holding local proxy.

**Not done / not claimed**: no rate limiting on Sentinel's own API; no TLS (proxy's job); production mode does not inspect the bind address.

## 5. Reliability and data integrity

- `app/timeutil.py`: all comparisons use naive UTC; offset-bearing inputs are converted, naive inputs assumed UTC. Stored alert timestamps keep the existing naive-ISO format, so historical rows are neither rewritten nor wrongly "refreshed" (tests: same instant with an offset is `unchanged`; later is `updated`).
- Alert ordering: `last_seen DESC, risk_score DESC, id ASC`.
- Rolling windows: boundaries pinned by tests (rate must be *strictly greater* than the threshold; a request exactly one window old is inside). `GET /api/findings` now ends the live window at an injectable clock (`create_app(clock=…)`), so an idle actor's burst expires; before, it stayed forever because the window ended at the actor's own last request. `POST /api/scan` is unaffected (still reports each actor's latest breaching window).
- Path normalization: percent-decoding per segment, `.`/`..`, duplicate/trailing slashes, `//` prefix, ASCII-only IDs, encoded `%2F` kept inside one segment; encoded IDs still count as distinct objects for enumeration.
- Out-of-order rows are sorted by time, not row id (test).
- Alert dedup/persistence across restarts: Phase 1 tests retained and pass.

## 6. Benchmark

### 6.1 Method

`cd backend && python3 -m benchmark.run --json out.json --markdown out.md` (committed results: `docs/benchmark/`). Pure synthetic traffic generated from a fixed epoch and a seeded RNG (`--seed`, default 20260105) and loaded into a temporary SQLite file; the live database is never involved (the module sets `DATABASE_URL` to a temp path before importing the app). The full pipeline runs: capture records → `POST /api/scan` → `GET /api/alerts` / `GET /api/shadow-apis`. 55 + 35 labelled instances (5 per scenario) with distinct IPs/credentials; 11 *tuning* scenarios and 7 *holdout* scenarios (§6.3). Two runs of the tuned build produce identical metrics (checked, and enforced by `tests/test_phase2_benchmark.py`); only wall-clock timings differ.

Ground truth per scenario: `expected` detection types must fire; `tolerated` types (e.g. a 30-request ID walk is also a burst) count neither way; any other type firing is a false positive. Unit of count = (instance × detection type). Alerts matching no labelled actor would count as false positives (there were none). Shadow APIs are scored per observed route against a hand-written list of two truly undocumented routes.

**Baseline** = the untouched Phase 1 commit `95009f0` (extracted with `git archive` into a scratch directory) run with the *same* benchmark code and scenarios. Phase 1 has no ownership-context feature, so it cannot detect confirmed BOLA; that is part of the measured difference, not an artefact.

**Label correction, disclosed**: my first draft labelled the "30-ID walk" scenario as enumeration only. The tuned build raised confirmed-BOLA alerts for it; on review the walk really does read orders 2–10 owned by others, so the alert is correct and the label was wrong. I fixed the label and re-ran **both** builds on the corrected label. The numbers below use the corrected label.

### 6.2 Results (synthetic; not real-world performance)

| | Baseline (Phase 1) | Phase 2 |
|---|---|---|
| **All 90 instances** TP / FP / TN / FN | 20 / 25 / 285 / 25 | 35 / 10 / 300 / 10 |
| precision / recall / F1 | 0.44 / 0.44 / 0.44 | 0.78 / 0.78 / 0.78 |
| false-positive rate | 0.081 | 0.032 |
| **Tuning set** (11 scenarios, in-sample) TP/FP/TN/FN | 15 / 15 / 170 / 15 | 30 / 0 / 185 / 0 |
| precision / recall / F1 / FPR | 0.50 / 0.50 / 0.50 / 0.081 | 1.00 / 1.00 / 1.00 / 0.000 |
| **Holdout set** (7 scenarios) TP/FP/TN/FN | 5 / 10 / 115 / 10 | 5 / 10 / 115 / 10 |
| precision / recall / F1 / FPR | 0.33 / 0.33 / 0.33 / 0.080 | 0.33 / 0.33 / 0.33 / 0.080 |
| Shadow APIs precision / recall | 0.50 / 1.00 (FPs: `/docs`, `/openapi.json`) | 1.00 / 1.00 |

Per detection type (all instances; TP FP TN FN → precision / recall):

| type | Baseline | Phase 2 |
|---|---|---|
| scraping | 10 20 50 5 → 0.33 / 0.67 | 15 10 60 0 → 0.60 / 1.00 |
| bola_enumeration | 5 0 80 5 → 1.00 / 0.50 | 5 0 80 5 → 1.00 / 0.50 |
| bola (confirmed, needs ownership context) | 0 0 80 10 → n/a / 0.00 | 10 0 80 0 → 1.00 / 1.00 |
| token_replay | 5 5 75 5 → 0.50 / 0.50 | 5 0 80 5 → 1.00 / 0.50 |

Per-scenario detection and false-alert rates are in `docs/benchmark/*.md`. Legitimate-traffic false positives: baseline flagged `legit_high_volume`, `repeated_small_set` and `roaming_user` in 5/5 instances each; Phase 2 flags none of them (tuning set).

Runtime (this machine, Python 3.14.5, 2 643 records; medians of 5; not deterministic): `POST /api/scan` 71 ms → 158 ms (the second scraping pass and ownership matching roughly doubled it), analysis alone 73 → 80 ms, `GET /api/shadow-apis` 17 → 25 ms. These are single-run laptop numbers on a small dataset, not a throughput claim.

### 6.3 What the holdout set shows

The holdout scenarios were written **after** the detector changes and never tuned on. Phase 2 does not improve them (F1 0.33 both). Per scenario:

| Holdout scenario | Result (both builds) | Why |
|---|---|---|
| `h_scrape_sequential_walk` | detected | distinct-path rule |
| `h_owner_reads_own`, `h_two_devices` | no alert (correct) | |
| `h_bola_slow_probe` (12 unknown IDs over 20 min) | **missed** | 300 s enumeration window |
| `h_replay_slow_distributed` (stolen token, 5 IPs, 30 min apart) | **missed** | indistinguishable from roaming by design |
| `h_nat_office` (6 users behind one IP) | **false alert** | scraping actor is the client IP |
| `h_partner_sync` (authorised full-catalogue read) | **false alert** | no allow-list for trusted clients |

The 1.00 on the tuning set is therefore an *in-sample* number: I wrote those scenarios and the rules together. The holdout is small and also mine; treat both as regression checks, not accuracy estimates.

### 6.4 Threshold and rule changes (every material one)

| Change | Old → new | Reason / measured effect |
|---|---|---|
| Scraping rate rule needs ≥ 5 distinct paths (`DEFAULT_MIN_DISTINCT_FOR_RATE`) | any > 10 req/60 s → > 10 req/60 s **and** ≥ 5 distinct | Removes false alerts for polling a few endpoints (`legit_high_volume`, `repeated_small_set`: 10 of 10 baseline FPs gone). Cost: a flood against one endpoint is no longer called scraping (belongs to rate limiting). `rate_threshold`, `distinct_threshold`, 60 s window unchanged. |
| Low-and-slow scraping | none → > 100 requests with ≥ 20 distinct paths in 3600 s | Catches `scraping_low_slow` (0 → 5/5). A heavy human browser could cross it; alerts are labelled `pattern: low_and_slow`. |
| Token replay needs concurrent use | > 3 IPs in 3600 s → also ≥ 4 IPs that switched within 60 s of the credential's previous request | Removes `roaming_user` FPs (5 → 0). Introduces the slow-distributed miss above. `rapid_switch_gap_seconds=None` restores the old rule. |
| Confirmed BOLA | none → 2xx read of an object owned by another user, given operator ownership context | See §6.5. |
| Enumeration, risk weights (BOLA 35 / scraping 30 / replay 35), escalation tiers, caps | unchanged | Score bounds 0–100 and breakdown-sums-to-score are covered by tests; findings now also carry `metadata.reasons`. |

### 6.5 BOLA, precisely

* **Enumeration** (`bola_enumeration`): capture-only *attempt* signal (> 10 distinct IDs, ≥ 50 % 401/403/404 in 300 s). It does not prove anything was read.
* **Confirmed** (`bola`): only when the operator supplies ownership context (`SENTINEL_OWNERSHIP_PATH` / `create_app(ownership=)`: object owners plus actor→user, keyed by credential fingerprint or IP) **and** the server answered 2xx. Without context no claim is made. It is as accurate as that context; the demo context comes from `python3 -m simulator.ownership` and contains fingerprints, never tokens. Unmapped actors, unowned objects and denied requests produce nothing (tests).
* Real-world deployments need their own source of ownership data; Sentinel cannot infer it from traffic.

## 7. Shadow APIs

- Two genuinely undocumented routes now exist in the controlled demo (`GET /shop/internal/export`, new `GET /shop/admin/stats`; neither is in `simulator/shop-openapi.json`). Both are detected in the benchmark and in a live uvicorn E2E run (§10), with documented routes reported separately (`documented` vs `shadow_apis`), and in `tests/test_demo_shop.py`.
- `/docs`, `/openapi.json`, `/redoc`, `/docs/oauth2-redirect` and Sentinel's own `/api/*` routes are hidden at read time (`storage.fetch_captured_requests(include_internal=False)`, applies to inventory, shadow, findings and scans). Capture already skipped them since Phase 1; the old rows stay in the database (test asserts the row count is unchanged).
- Specs: JSON only, ≤ 2 MiB, needs a `paths` object; malformed/missing/oversized/off-limits inputs are handled and tested. **Open question** from `docs/backend-contract.md` ("YAML needed for judging?") is unresolved; no YAML dependency was added.

## 8. Deployment readiness

See `docs/DEPLOYMENT.md` (local vs production tables, config reference, start/stop, reverse proxy, health and troubleshooting, retention, OpenAPI limits).
- `python3 -m app.maintenance` — dry-run-by-default retention with optional pre-delete backup; `open`/`acknowledged` alerts never pruned; nothing automatic (`tests/test_phase2_maintenance.py`).
- `requirements.txt` now lists only imported packages with the minimum versions the suite ran on; `requirements-dev.txt` adds pytest/httpx. No upper bounds were tested.
- Static checks: no formatter/linter (`ruff`, `black`, `flake8`, `mypy`) is installed or configured in the repository, so none was run. `python3 -m compileall` succeeded and a small AST script found no unused imports in new/changed modules.

## 9. Tests

Command: `cd backend && python3 -m pytest tests -q` → **202 passed** (134 original + 68 new) in ~11 s, no failures, no skips. Run again with the live-database guard active.

Existing tests I **changed** (behaviour changed on purpose; none were loosened to make them pass, but you should review these edits):
- `test_shadow_apis.py` (all tests that build an app; 19 changed lines): pass `spec_dir` because `spec_path` is now confined; `/api/health` seed row is now hidden (documented count 3 → 2, `/api/health` no longer "documented"); the "missing spec" path now ends in `.json`.
- `test_demo_shop.py`, `test_demo_proxy.py`: `spec_dir`; the simulator now exercises two shadow routes.
- `test_findings.py::test_end_to_end_live_capture_to_findings`: hits 15 *different* items instead of one URL 15 times (the single-URL case is now a deliberate non-finding, covered by `test_polling_one_endpoint_is_not_scraping…`).
- `test_analysis_pipeline.py::…active_window…`: the 12-request burst now spans 12 distinct paths for the same reason.

New files: `test_phase2_security.py`, `test_phase2_reliability.py`, `test_phase2_detectors.py`, `test_phase2_maintenance.py`, `test_phase2_benchmark.py`, plus one test appended to `test_demo_shop.py` (live fingerprint → ownership → confirmed-BOLA).

## 10. End-to-end verification (isolated)

A real `uvicorn app.main:app` on port 8765 with a scratch database, a generated key/secret (never printed), the demo shop, `simulator.run` traffic and a generated ownership file: `GET /api/health` → ok/ok; scan created 5 alerts (confirmed `bola` 55, `bola_enumeration` 45, two `scraping` 40, `token_replay` 35); scan without a key → 401; shadow routes = `/shop/admin/stats`, `/shop/internal/export`, 3 documented; `spec_path=/etc/passwd` → 400 generic; the secret query value appeared 0 times in the server log and the database; the ownership file contained 0 raw tokens; the live DB was unchanged.
Not done: no browser test of the dashboard page (NOT VERIFIED); the live :8000/:8080 instances were not exercised.

## 11. Frontend decision

No evaluation criteria in the repository mention a frontend, so whether a "real" `frontend/` is required is **NOT VERIFIED**. I did not build one. The demo dashboard (`demo/`) was later upgraded in place, still without a framework or a `frontend/` app; see §15. Its limits: single page, throwaway, proxy holds the admin key for anyone with local access to :8080, no pagination, no auth of its own. If judging requires a frontend, the smallest step is hardening this page, not a rewrite.

## 12. Known limitations / unresolved

- Benchmark is synthetic and self-authored; holdout shows four unresolved patterns (§6.3).
- Scraping/NAT: the actor is the client IP, so many users behind one IP can look like one scraper; trusted-client allow-lists do not exist.
- Slow distributed credential abuse and slow ID probing are not detected.
- Confirmed BOLA depends on externally supplied ownership data.
- Findings view is a live one-minute window by design; use scans for history.
- Alerts have no retention automation and no per-alert history beyond `occurrences`.
- YAML OpenAPI, `servers`/`basePath` prefixes and `$ref` files unsupported.
- Production mode is a config gate, not a security audit; no penetration test, load test or multi-process test was done (SQLite, single process assumed).
- `shadow_detection.py` and `routes/analytics.py` are empty files; left in place.
- Live services still run Phase 1 code until restarted with the commands in `docs/HACKATHON_HANDOFF.md`.

## 13. Acceptance criteria

| Criterion | Result | Evidence |
|---|---|---|
| Phase 1 functionality preserved | PASS | 134 original tests pass (5 edited as listed); E2E run |
| Security gaps repaired and tested | PASS | §4 (negative and positive tests) |
| Timestamp / rolling-window edge cases covered | PASS | `test_phase2_reliability.py` |
| No unexpected database writes during tests | PASS | session guard in `conftest.py`; live DB mtime unchanged |
| Scraping, BOLA, replay scenarios verified | PASS (with holdout misses) | tests + benchmark; limits in §6.3 |
| ≥ 2 genuine shadow endpoints detected | PASS | benchmark, `test_demo_shop.py`, E2E |
| Benchmark reproducible and evidence-based | PASS | identical repeat runs; test enforces |
| Baseline vs tuned on identical scenarios | PASS | same code and data; baseline = `95009f0` |
| Legitimate-traffic FPs measured | PASS | §6.2; holdout still has 2 FP scenarios |
| Credentials protected | PASS | tests on alerts/DB/log; E2E; no secrets in diff scan |
| Full suite result | PASS | 202 passed at the end of Phase 2; 230 after the dashboard addendum (§15) |
| Demo startup/operation documented | PASS | HANDOFF + DEPLOYMENT + README |
| Report and handoff accurate | PASS (subject to your review) | |
| Existing work and backup preserved | PASS | old backup untouched; new backup verified (51 files) |
| Real frontend required | NOT VERIFIED | no criteria available |
| Dashboard rendered in a browser | NOT VERIFIED | not run |
| Live :8000/:8080 services on Phase 2 code | NOT VERIFIED | not restarted by design |

## 14. Commands and backups

```bash
cd backend
python3 -m pytest tests -q                                              # 202 passed
python3 -m benchmark.run --json out.json --markdown out.md              # tuned build, isolated
python3 -m app.maintenance --db <file> --captures-days 30               # retention dry run
python3 -m simulator.ownership > ownership.json                         # needs SENTINEL_FP_SECRET
```

Baseline reproduction (read-only, no checkout): `git archive 95009f0 backend | tar -x -C <scratch>`, copy `backend/benchmark/` into the extracted `backend/`, run `python3 -m benchmark.run` there. Committed results: `docs/benchmark/baseline-phase1.{json,md}` and `tuned-phase2.{json,md}`; their `timings_not_deterministic` blocks are machine- and run-specific.

Backups (outside the repository; tracked + new files only, no databases, logs, caches or secrets):
- `~/.api-sentinel-backups/phase2-20261015-112752/` — tracked files at `95009f0` before any edit.
- `~/.api-sentinel-backups/phase2-final-20261015-114344/` — `working-tree.tar` (70 files, the finished Phase 2 tree), `tracked.diff`, `HEAD.txt`, `STATUS.txt`.

## 15. Addendum: dashboard upgrade (after Phase 2 acceptance)

Acceptance re-check before editing: branch `jisan`, HEAD `95009f0`, 38 changed paths as documented, all three backups present, the final snapshot matched the tree (except this report, to which §14 was appended afterwards), 202 tests passed in isolation, live DB unchanged. One mismatch found and fixed: a wrong cross-reference in §2.

Changed (no framework, no new dependency; `frontend/` still not created):
- `demo/index.html` (structure + the sample-traffic data block, now also hitting `/shop/admin/stats`), new `demo/dashboard.css`, new `demo/dashboard.js`.
- `demo/serve.py`: static allowlist extended to exactly `/`, `/index.html`, `/dashboard.css`, `/dashboard.js`; every response now carries `Content-Security-Policy` (`default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, no inline code anywhere), `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Cache-Control: no-store`. Key injection, route allowlist, Host/Origin/Content-Type/size checks are untouched.
- Dashboard features: connection/health pill, summary cards computed only from fetched data, alerts with status filter, per-alert status + analyst note with success/failure feedback (unsaved edits survive refreshes), live findings (labelled as unstored rolling windows), shadow APIs vs documented routes (with an explicit "no specification loaded, nothing confirmed" state), inventory with a Spec column and filter, loading/empty/error states with Retry, one-action-at-a-time button locking, optional 15 s auto-refresh that pauses while you edit a note, responsive stacked layout, light/dark theme, keyboard-focusable scroll regions.
- Tests: `backend/tests/test_dashboard.py` (28 new): static allowlist, headers, no key in any file, no unsafe DOM insertion patterns, no inline script/style/handlers/external URLs, every element id used by the script exists, `node --check`. `test_demo_proxy.py` now expects both shadow routes from the sample traffic.
- Result: `python3 -m pytest tests -q` → **230 passed**.

Browser verification (headless Chrome 15 Oct, driven over the DevTools protocol against an isolated backend :8765 and the real proxy :8766; Chrome, Node and the harness are scratch tooling outside the repo): page loaded with no JavaScript exceptions and no CSP violations; empty states; double-click on Generate sample traffic ran once (all three buttons disabled while running); sample traffic → 30×200; scan created 6 alerts (confirmed BOLA 55, BOLA enumeration 45, 3 scraping 40, token replay 35); triage status and note saved and re-rendered from the server's response; filter chips; both shadow routes shown as `shadow`, documented routes as `documented`; a hostile path (`<img … onerror=…>`) captured as traffic rendered as inert text; `spec_path=/etc/passwd` showed the generic 400 message; backend killed → "Backend unreachable", every section in an error state with Retry, counts cleared (a stale-count bug found and fixed during this check), scan failure explained; no horizontal overflow at 390 px and 820 px width; light and dark screenshots reviewed. Server log and proxy log contained no key.

Not verified: other browsers (Safari/Firefox), a real phone, screen-reader behaviour, the live :8000/:8080 instances (not touched), more than ~10 alerts (no pagination; very long tables just scroll). The mobile layout of a six-alert list is long (stacked cards).
