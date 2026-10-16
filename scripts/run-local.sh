#!/usr/bin/env bash
# Start, check or stop a matching API Sentinel backend + dashboard proxy from THIS checkout.
#
#   scripts/run-local.sh start  <env-file>
#   scripts/run-local.sh status <env-file>
#   scripts/run-local.sh stop   <env-file>
#
# The env file (template: docs/examples/local.env.example) must live OUTSIDE the
# repository and be readable only by you (chmod 600). It is sourced as shell code.
# Required: SENTINEL_API_KEY, SENTINEL_FP_SECRET, DATABASE_URL (absolute sqlite:////...).
# Optional: BACKEND_PORT (9101), DASHBOARD_PORT (9102), SENTINEL_ENV, SENTINEL_GATEWAY_CONFIG,
#   SENTINEL_PRINCIPALS_PATH, SENTINEL_RATE_LIMITS_PATH, OPENAPI_SPEC_PATH, SENTINEL_SPEC_DIR,
#   SENTINEL_OWNERSHIP_PATH, ENABLE_DEMO_TARGET, TRUST_PROXY_IPS (comma list; unset = no
#   X-Forwarded-For trust, i.e. uvicorn --no-proxy-headers).
#
# Python: backend/.venv/bin/python when that project venv exists (create it with
#   python3 -m venv backend/.venv && backend/.venv/bin/pip install -r backend/requirements.txt),
#   otherwise python3 from PATH.
#
# Safety: never kills or reuses a port it did not open (busy port = refuse), only stops
# PIDs it recorded itself, never prints secret values. Logs and PID files go to
# "<env-file>.run/".
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CMD="${1:-}"; ENV_FILE="${2:-}"
die() { echo "run-local: $*" >&2; exit 1; }
[[ "$CMD" =~ ^(start|status|stop)$ && -n "$ENV_FILE" ]] || die "usage: $0 start|status|stop <env-file>"
[[ -f "$ENV_FILE" ]] || die "env file not found: $ENV_FILE"
ENV_FILE="$(cd "$(dirname "$ENV_FILE")" && pwd)/$(basename "$ENV_FILE")"
RUN_DIR="$ENV_FILE.run"

case "$ENV_FILE" in "$REPO"/*) die "keep the env file outside the repository (it holds secrets)";; esac
perms="$(stat -f '%Lp' "$ENV_FILE" 2>/dev/null || stat -c '%a' "$ENV_FILE")"
[[ "$perms" =~ ^[0-7]00$ ]] || die "env file must be readable only by you: chmod 600 '$ENV_FILE'"

set -a; . "$ENV_FILE"; set +a
BACKEND_PORT="${BACKEND_PORT:-9101}"; DASHBOARD_PORT="${DASHBOARD_PORT:-9102}"
PY="$REPO/backend/.venv/bin/python"; [[ -x "$PY" ]] || PY="$(command -v python3)"

listening() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | head -1; }
ours() {  # PID from our file, still alive and still running from this checkout
  local f="$RUN_DIR/$1.pid" pid
  [[ -f "$f" ]] || return 1
  pid="$(cat "$f")"
  kill -0 "$pid" 2>/dev/null || return 1
  lsof -p "$pid" -a -d cwd -Fn 2>/dev/null | grep -q "^n$REPO" || return 1
  echo "$pid"
}
summary() {  # what is running, read through the dashboard proxy (it adds the key; we never print it)
  echo "python    $PY (used by start; $("$PY" -c 'import yaml' 2>/dev/null && echo 'PyYAML available' || echo 'PyYAML MISSING: YAML specs cannot be read; pip install -r backend/requirements.txt'))"
  "$PY" - "$BACKEND_PORT" "$DASHBOARD_PORT" "$REPO" <<'PY'
import json, sys, urllib.request
b, d, repo = sys.argv[1:4]
sys.path.insert(0, f"{repo}/backend")
from app.config import API_REVISION
def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.load(r)
h = get(f"http://127.0.0.1:{b}/api/health")
p = get(f"http://127.0.0.1:{d}/api/proxy-status")
lim = get(f"http://127.0.0.1:{d}/api/rate-limits")
ok = h.get("api_revision") == API_REVISION and p.get("backend") == "ok" and p.get("proxy_revision")
print(f"backend   http://127.0.0.1:{b}  status={h['status']} database={h['database']} api_revision={h.get('api_revision')} (this checkout: {API_REVISION})")
print(f"dashboard http://127.0.0.1:{d}  proxy_revision={p.get('proxy_revision')} key accepted by backend: {p.get('backend')}")
print(f"gateway   {'ON' if lim['gateway_enabled'] else 'off (SENTINEL_GATEWAY_CONFIG not set)'}")
shop = any(i["endpoint"].startswith("GET /shop/") for i in lim["items"])
print("demo shop " + ("mounted (ENABLE_DEMO_TARGET=true, development only)" if shop
      else "NOT mounted: 'Generate sample traffic' will report it; set ENABLE_DEMO_TARGET=true for the local demo"))
vp = lim["vp_principals"]
print(f"principals {lim['principals_configured']} registered, {vp} with VP quota"
      + ("" if vp else "  <- nobody gets the VP quota (no VP principal configured)"))
print(f"limits    {len(lim['items'])} endpoints, window {lim['window_seconds']} s, VP = {lim['vp_multiplier']}x normal")
sys.exit(0 if ok else 3)
PY
}

case "$CMD" in
status)
  for n in backend proxy; do
    if pid="$(ours $n)"; then echo "$n: running (pid $pid)"; else echo "$n: not running (from this script)"; fi
  done
  summary || die "running processes are not a compatible, working pair (see above)"
  ;;
stop)
  for n in proxy backend; do
    if pid="$(ours $n)"; then
      kill "$pid"
      # Wait for a graceful exit so an immediate `start` finds the port free (no SIGKILL escalation).
      for _ in $(seq 1 60); do kill -0 "$pid" 2>/dev/null || break; sleep 0.25; done
      if kill -0 "$pid" 2>/dev/null; then
        echo "run-local: $n (pid $pid) is still shutting down after 15 s; not forcing it" >&2
      else
        echo "stopped $n (pid $pid)"
      fi
    else
      echo "$n: nothing of ours to stop"
    fi
    rm -f "$RUN_DIR/$n.pid"
  done
  ;;
start)
  for v in SENTINEL_API_KEY SENTINEL_FP_SECRET DATABASE_URL; do
    [[ -n "${!v:-}" ]] || die "$v is not set in the env file"
  done
  [[ "$DATABASE_URL" == sqlite:////* ]] || die "DATABASE_URL must be an absolute path: sqlite:////full/path/file.db"
  [[ "${SENTINEL_ENV:-development}" =~ ^(development|production)$ ]] || die "SENTINEL_ENV must be development or production"
  if [[ "${SENTINEL_ENV:-development}" == production && "$(echo "${ENABLE_DEMO_TARGET:-false}" | tr '[:upper:]' '[:lower:]')" =~ ^(1|true|yes)$ ]]; then
    die "ENABLE_DEMO_TARGET=true is refused in production (the demo shop is deliberately vulnerable); set it to false"
  fi
  for port in "$BACKEND_PORT" "$DASHBOARD_PORT"; do
    [[ -z "$(listening "$port")" ]] || die "port $port is already in use; stop that service yourself or choose another port (nothing was changed)"
  done
  mkdir -p "$RUN_DIR"; chmod 700 "$RUN_DIR"
  if [[ -n "${TRUST_PROXY_IPS:-}" ]]; then PROXY_FLAGS=(--proxy-headers "--forwarded-allow-ips=$TRUST_PROXY_IPS"); else PROXY_FLAGS=(--no-proxy-headers); fi
  ( cd "$REPO/backend" && exec "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port "$BACKEND_PORT" "${PROXY_FLAGS[@]}" \
      >"$RUN_DIR/backend.log" 2>&1 ) &
  echo $! > "$RUN_DIR/backend.pid"
  for _ in $(seq 1 40); do
    curl -fs "http://127.0.0.1:$BACKEND_PORT/api/health" >/dev/null 2>&1 && break
    kill -0 "$(cat "$RUN_DIR/backend.pid")" 2>/dev/null || { tail -5 "$RUN_DIR/backend.log" >&2; rm -f "$RUN_DIR/backend.pid"; die "backend failed to start (configuration refused?)"; }
    sleep 0.5
  done
  ( cd "$REPO" && DEMO_PORT="$DASHBOARD_PORT" BACKEND_URL="http://127.0.0.1:$BACKEND_PORT" exec python3 demo/serve.py \
      >"$RUN_DIR/proxy.log" 2>&1 ) &
  echo $! > "$RUN_DIR/proxy.pid"
  for _ in $(seq 1 20); do curl -fs "http://127.0.0.1:$DASHBOARD_PORT/" >/dev/null 2>&1 && break; sleep 0.5; done
  summary || { echo "run-local: started, but the pair is not compatible or the key is refused (above)" >&2; exit 3; }
  echo "logs: $RUN_DIR   stop with: $0 stop $ENV_FILE"
  ;;
esac
