# API Sentinel source-code scanner — Python-first implementation

## What is included

- `backend/app/source_scanner.py`: static scanner; Python route detection uses `ast` (no import or execution), with best-effort regex detectors for common JavaScript/TypeScript, Spring, Go, Laravel, and Rails patterns.
- `backend/app/routes/source_scan.py`: authenticated scan and query endpoints; secure public-GitHub retrieval, ZIP upload, and allow-listed local-directory scan.
- `backend/tests/test_source_scanner.py`: scanner persistence, source location, language pattern, removed-route, and file-skip tests.
- `backend/tests/test_source_scan_api.py`: API-key enforcement, ZIP upload, ZIP traversal, and input validation tests.
- `integration.patch`: adds router/config wiring to existing `backend/app/main.py` and `backend/app/config.py`.

## Apply and test

Unzip this bundle at the repository root, copy its `backend/` tree into the repository (preserving the new files), then apply `integration.patch` from the repository root:

```bash
git apply integration.patch
cd backend
python -m pytest -q tests/test_source_scanner.py tests/test_source_scan_api.py
```

The existing repository already uses FastAPI, Pydantic, and SQLite; no new runtime dependency is required. The GitHub integration cannot push branches in this session, so these changes are provided as a patch bundle and have not been committed to your repository.

## Input APIs

### 1. Public GitHub repository

```http
POST /api/source-scan
X-Sentinel-Key: <SENTINEL_API_KEY>
Content-Type: application/json
```

```json
{"source_type":"github","repo_url":"https://github.com/owner/repo","project_id":"my-project"}
```

Only public repositories are supported in this first version. A public repository archive is fetched without forwarding credentials.

### 2. Uploaded ZIP

Send raw ZIP bytes (not multipart) to `POST /api/source-scan/upload?project_id=my-project` with `Content-Type: application/zip` and `X-Sentinel-Key`.

### 3. Local directory

Set `SENTINEL_SCAN_ROOTS` to one or more trusted root directories separated by the platform path separator. For example, on Windows use `C:\\Users\\you\\source-projects`; on Linux use `/srv/source-projects`. Then call:

```json
{"source_type":"local","local_path":"C:\\Users\\you\\source-projects\\my-app","project_id":"my-app"}
```

Local scanning is disabled when the allow-list is unset. Paths outside the configured roots are rejected.

### Query stored source routes

`GET /api/source-apis?project_id=my-project` returns currently present routes. Add `include_absent=true` to inspect historical rows that disappeared from a later scan. Rows include HTTP method, normalized path, source filename, line number, detector, confidence, and first/last seen timestamps.

## Limits and security

- Source is read and parsed, never imported or executed.
- GitHub URL host and redirects are restricted to GitHub-controlled hosts; private repositories are rejected.
- Compressed archives are limited to 20 MiB, expanded contents to 80 MiB, and archive members to 5,000.
- ZIP path traversal, symlinks, and special files are rejected.
- Individual source files above 2 MiB and common dependency/build directories are skipped.
- Scan/write endpoints require a configured `SENTINEL_API_KEY`; otherwise writes are disabled. Read access follows Sentinel's existing policy.
- Source routes are stored separately in `source_code_apis`; they are not mixed with observed `captured_requests`.

## Interpretation and next stages

Static source discovery is evidence of a route declaration, not proof that the endpoint is deployed or reachable. The first version can miss dynamic route construction, imported router prefixes, framework conventions, and generated routes. It also does not yet resolve effective prefixes from `include_router()` or framework mounts. Next, add explicit router-prefix resolution and confidence/evidence explanations; then compare three inventories: source-declared routes, traffic-observed routes, and OpenAPI-documented routes. A shadow API should be reported as *observed in traffic but undocumented*; a source-only route is *declared in source but not yet observed*, not a confirmed shadow API.

Quota enforcement is a separate runtime concern: only traffic routed through Sentinel's gateway/proxy can be reliably rejected with 429. A static scanner can inform policy defaults, but cannot enforce quotas on traffic that bypasses the gateway. For multi-worker deployment, move rate-limit counters from in-memory state to shared storage (for example Redis or atomic database windows) before claiming global quotas.

## Validation performed for this bundle

- `tests/test_source_scanner.py`: 3 passed.
- `tests/test_source_scan_api.py`: 5 passed in an isolated FastAPI test app with the repository's existing `app.auth` contract represented by a temporary test shim. The shim is not included in the bundle. Run both suites after applying the integration patch in the full repository to verify the exact integrated application.
