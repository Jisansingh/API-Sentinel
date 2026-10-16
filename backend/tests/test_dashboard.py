"""Dashboard files and proxy hardening: static allowlist, security headers,
no key in any served file, no unsafe DOM insertion, JS wiring matches the HTML."""

import importlib.util
import json
import re
import shutil
import socket
import subprocess
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

DEMO = Path(__file__).resolve().parents[2] / "demo"
KEY = "d" * 40
INDEX = (DEMO / "index.html").read_text()
JS = (DEMO / "dashboard.js").read_text()
CSS = (DEMO / "dashboard.css").read_text()


@pytest.fixture
def proxy(monkeypatch):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setenv("BACKEND_URL", "http://127.0.0.1:1")  # closed port: proxied calls give 502
    monkeypatch.setenv("DEMO_PORT", str(port))
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    spec = importlib.util.spec_from_file_location(f"serve_{port}", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = ThreadingHTTPServer(("127.0.0.1", port), module.DemoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as err:
        return err.code, err.headers, err.read().decode()


# --- what the proxy serves --------------------------------------------------------

@pytest.mark.parametrize("path,ctype", [("/", "text/html"), ("/index.html", "text/html"),
                                        ("/dashboard.css", "text/css"), ("/dashboard.js", "javascript")])
def test_dashboard_files_are_served(proxy, path, ctype):
    status, headers, body = _get(proxy + path)
    assert status == 200 and ctype in headers["Content-Type"] and body


@pytest.mark.parametrize("path", ["/serve.py", "/__pycache__/", "/dashboard.js?x=1", "/dashboard.css/..",
                                  "/../backend/app/main.py", "/demo", "/favicon.ico"])
def test_nothing_else_is_served(proxy, path):
    assert _get(proxy + path)[0] == 404


def test_security_headers_on_pages_and_proxied_responses(proxy):
    for path in ("/", "/dashboard.js", "/api/health", "/serve.py"):  # incl. proxied 502 and a 404
        _, headers, _ = _get(proxy + path)
        csp = headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp
        assert "unsafe-inline" not in csp and "unsafe-eval" not in csp and "default-src 'none'" in csp
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["Cache-Control"] == "no-store"


def test_wrong_host_header_is_still_refused(proxy):
    req = urllib.request.Request(proxy + "/dashboard.js", headers={"Host": "evil.example"})
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(req, timeout=10)
    assert err.value.code == 403


# --- secrets and unsafe patterns -------------------------------------------------------

def test_no_key_or_key_header_in_any_dashboard_file(proxy):
    for name in ("index.html", "dashboard.js", "dashboard.css"):
        text = (DEMO / name).read_text()
        assert KEY not in text and "X-Sentinel-Key" not in text and "SENTINEL_API_KEY=" not in text
    for path in ("/", "/dashboard.js", "/dashboard.css"):
        assert KEY not in _get(proxy + path)[2]


@pytest.mark.parametrize("pattern", [r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write",
                                     r"\beval\s*\(", r"new Function", r"setTimeout\(\s*[\"'`]",
                                     r"\.srcdoc", r"createContextualFragment"])
def test_js_never_builds_html_from_strings(pattern):
    assert not re.search(pattern, JS)


def test_page_has_no_inline_code_styles_handlers_or_external_urls():
    scripts = re.findall(r"<script([^>]*)>(.*?)</script>", INDEX, re.S)
    for attrs, body in scripts:
        assert "src=" in attrs or 'type="application/json"' in attrs, "inline executable script"
    assert not re.search(r"\sstyle\s*=", INDEX) and not re.search(r"<style", INDEX)
    assert not re.search(r"\son[a-z]+\s*=", INDEX, re.I)
    for name, text in (("html", INDEX), ("js", JS), ("css", CSS)):
        urls = [u for u in re.findall(r"https?://[^\s\"'<>)]+", text) if "www.w3.org/2000/svg" not in u]
        assert not urls, f"{name} references an external URL: {urls}"


# --- wiring ---------------------------------------------------------------------------

def test_every_element_id_used_by_the_script_exists_in_the_page():
    html_ids = set(re.findall(r'\sid="([^"]+)"', INDEX))
    used = set(re.findall(r'\$\("([^"]+)"\)', JS))
    used |= set(re.findall(r'"((?:btn-[a-z-]+|[a-z]+-(?:body|count)))"', JS))
    assert used and used <= html_ids, sorted(used - html_ids)


def test_page_references_only_its_own_assets_and_keeps_the_traffic_plan():
    assert '<link rel="stylesheet" href="/dashboard.css">' in INDEX
    assert '<script src="/dashboard.js" defer></script>' in INDEX
    plan = re.search(r'id="sample-traffic">(.*?)</script>', INDEX, re.S).group(1)
    assert "/shop/admin/stats" in plan and "/shop/internal/export" in plan


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_dashboard_script_parses():
    result = subprocess.run(["node", "--check", str(DEMO / "dashboard.js")], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


def test_labels_keep_live_findings_and_stored_alerts_distinct():
    assert "Persistent alerts" in INDEX and "Live findings" in INDEX
    assert re.search(r"Not stored", INDEX) and re.search(r"Only <strong>Run scan</strong>", INDEX)


def test_scoring_explanation_matches_backend():
    """The page's severity bands and scoring text must not drift from the backend."""
    from app import analysis
    from app.risk_scoring import RiskScorer

    s = RiskScorer()
    # bands: backend guidance text switches at 40 and 70
    assert s.calculate_score(scraping_detected=True).reasons[-1].startswith("Low risk")  # 30
    assert 'score >= 70 ? "high" : score >= 40 ? "medium" : "low"' in JS
    assert "Medium 40&ndash;69, Low &lt; 40" in INDEX
    assert f"BOLA {s.BOLA_WEIGHT}, scraping {s.SCRAPING_WEIGHT}, token replay {s.TOKEN_REPLAY_WEIGHT}" in INDEX
    assert [pts for _, pts in s.MAGNITUDE_TIERS] == [30, 20, 10] and s.CONTEXT_POINTS == 10
    for segment in s.SENSITIVE_SEGMENTS:
        assert segment in INDEX
    assert analysis.DEFAULT_RATE_THRESHOLD == 10 and analysis.DEFAULT_MIN_DISTINCT_FOR_RATE == 5
    assert analysis.DEFAULT_DISTINCT_THRESHOLD == 20 and analysis.SLOW_REQUEST_THRESHOLD == 100
    assert analysis.DEFAULT_ENUM_DISTINCT_IDS == 10 and analysis.DEFAULT_ENUM_DENIED_RATIO == 0.5
    assert analysis.DEFAULT_MAX_IP_CHANGES == 3 and analysis.REPLAY_SWITCH_GAP_SECONDS == 60


# --- startup key self-check (the "401 in the dashboard" diagnosis) ---------------------

class _Backend(BaseHTTPRequestHandler):
    code = 200
    seen_keys: list = []

    def do_GET(self):
        _Backend.seen_keys.append(self.headers.get("X-Sentinel-Key"))
        self.send_response(_Backend.code)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


def _serve_module(monkeypatch, key, backend_url):
    monkeypatch.setenv("BACKEND_URL", backend_url)
    monkeypatch.setenv("DEMO_PORT", "8099")
    if key is None:
        monkeypatch.delenv("SENTINEL_API_KEY", raising=False)
    else:
        monkeypatch.setenv("SENTINEL_API_KEY", key)
    spec = importlib.util.spec_from_file_location("serve_selfcheck", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def stub_backend():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Backend)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    _Backend.code, _Backend.seen_keys = 200, []
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


@pytest.mark.parametrize("code,expected", [(200, "accepted"), (401, "REJECTED"), (500, "HTTP 500")])
def test_startup_check_reports_backend_verdict_without_leaking_key(monkeypatch, stub_backend, code, expected):
    _Backend.code = code
    message = _serve_module(monkeypatch, KEY, stub_backend).check_backend_key()
    assert expected in message and KEY not in message
    assert _Backend.seen_keys == [KEY]  # the real key was what got checked


def test_startup_check_flags_missing_short_and_unreachable_keys(monkeypatch, stub_backend):
    assert "NOT set" in _serve_module(monkeypatch, None, stub_backend).check_backend_key()
    short = "x" * 17
    message = _serve_module(monkeypatch, short, stub_backend).check_backend_key()
    assert "shorter than 32" in message and short not in message
    assert _Backend.seen_keys == []  # a key that cannot be valid is never sent
    assert "not reachable" in _serve_module(monkeypatch, KEY, "http://127.0.0.1:1").check_backend_key()


def test_proxy_keys_the_access_control_reads_but_nothing_new_is_writable():
    spec = importlib.util.spec_from_file_location("serve_routes", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in ("/api/rate-limits", "/api/gateway-events"):
        assert module.KEYED_ROUTES["GET"].match(path)
        assert not module.KEYED_ROUTES["POST"].match(path) and not module.KEYED_ROUTES["PATCH"].match(path)
    assert "/api/gateway-events" in JS and "/api/rate-limits" in JS and 'id="access-body"' in INDEX


# --- the dashboard may only call endpoints the running app and proxy really provide ------------

PROXY_ONLY = {"/api/proxy-status"}  # answered by demo/serve.py itself, never by the backend


def test_every_endpoint_the_dashboard_calls_exists(tmp_path):
    """Regression: the Access control panel showed HTTP 404 because the page asked for endpoints
    a (stale) backend did not register. The current source must provide every path the page uses."""
    from app.main import create_app

    served = set(create_app(db_path=str(tmp_path / "d.db")).openapi()["paths"])
    called = set(re.findall(r'"(/api/[a-z-]+)', JS))
    assert {"/api/rate-limits", "/api/gateway-events"} <= called
    for path in called - PROXY_ONLY:
        assert any(s == path or s.startswith(path + "/") for s in served), path
    serve_source = (DEMO / "serve.py").read_text()
    for path in PROXY_ONLY:
        assert f'self.path == "{path}"' in serve_source and path not in served


@pytest.fixture
def keyed_proxy(monkeypatch, stub_backend):
    """The real DemoHandler in front of a stub backend that records the key it receives."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    monkeypatch.setenv("BACKEND_URL", stub_backend)
    monkeypatch.setenv("DEMO_PORT", str(port))
    monkeypatch.setenv("SENTINEL_API_KEY", KEY)
    spec = importlib.util.spec_from_file_location(f"serve_keyed_{port}", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = ThreadingHTTPServer(("127.0.0.1", port), module.DemoHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def test_proxy_forwards_access_control_reads_with_the_key_and_never_returns_it(keyed_proxy):
    for path in ("/api/rate-limits", "/api/gateway-events?limit=100"):
        status, headers, body = _get(keyed_proxy + path)
        assert status == 200 and body == "{}"
        assert KEY not in body and not any(KEY in v for v in headers.values())
    assert _Backend.seen_keys == [KEY, KEY]  # attached server-side, once per request


def test_backend_access_control_endpoints_need_the_admin_key(tmp_path):
    from fastapi.testclient import TestClient

    from app.main import create_app

    app = create_app(db_path=str(tmp_path / "k.db"), api_key=KEY)
    c = TestClient(app)
    for path in ("/api/rate-limits", "/api/gateway-events"):
        assert c.get(path).status_code == 401
        assert c.get(path, headers={"X-Sentinel-Key": "w" * 40}).status_code == 401
        assert c.get(path, headers={"X-Sentinel-Key": KEY}).status_code == 200


def test_dashboard_explains_a_backend_that_lacks_the_access_control_endpoints():
    assert "{ status: res.status }" in JS
    assert "does not provide /api/rate-limits or /api/gateway-events" in JS and "restart it" in JS



# --- version handshake: a stale backend or proxy is reported, not hidden ----------------------

def test_dashboard_revisions_match_backend_and_proxy():
    from app.config import API_REVISION

    spec = importlib.util.spec_from_file_location("serve_rev", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert f"const REQUIRED_API_REVISION = {API_REVISION};" in JS
    assert f"const REQUIRED_PROXY_REVISION = {module.PROXY_REVISION};" in JS
    assert "Version mismatch" in JS and 'return "mismatch"' in JS
    assert "if (state.mismatch) throw new Error(state.mismatch);" in JS  # panel names the stale process


def test_proxy_status_reports_its_revision_without_the_key(keyed_proxy):
    status, headers, body = _get(keyed_proxy + "/api/proxy-status")
    assert status == 200 and json.loads(body) == {"backend": "ok", "proxy_revision": 6}
    assert KEY not in body


def test_dashboard_warns_when_nobody_has_the_vp_quota():
    assert "no VP principals configured: nobody gets the VP quota" in JS


def test_run_local_script_is_valid_and_guards_ports_and_secrets():
    script = (DEMO.parent / "scripts" / "run-local.sh").read_text()
    if shutil.which("bash"):
        assert subprocess.run(["bash", "-n", str(DEMO.parent / "scripts" / "run-local.sh")]).returncode == 0
    assert "already in use" in script and "chmod 600" in script and "outside the repository" in script
    assert "sqlite:////" in script and "--no-proxy-headers" in script
    assert "kill -9" not in script and "pkill" not in script and "killall" not in script


# --- demo shop availability is configured explicitly and reported clearly -----------------------

def test_dashboard_reports_a_missing_demo_shop_without_hiding_other_errors():
    assert "The demo shop is not mounted on this backend" in JS and "ENABLE_DEMO_TARGET=true (development only" in JS
    assert "codes.every((c) => c === 404)" in JS            # only an all-404 run is called "not mounted"
    assert "Sent ${plan.length} requests (${summary})" in JS  # any other mix of statuses is shown as-is


def test_local_env_template_enables_the_shop_for_development_only():
    template = (DEMO.parent / "docs" / "examples" / "local.env.example").read_text()
    assert "\nENABLE_DEMO_TARGET=true\n" in template and "\nSENTINEL_ENV=development\n" in template
    assert "refused when SENTINEL_ENV=production" in template


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not installed")
@pytest.mark.parametrize("demo", ["true", "TRUE", "1", "yes"])
def test_run_local_refuses_production_with_the_demo_shop(tmp_path, demo):
    env = tmp_path / "prod.env"
    env.write_text(f"SENTINEL_API_KEY={'k' * 40}\nSENTINEL_FP_SECRET={'f' * 40}\n"
                   f"DATABASE_URL=sqlite:///{tmp_path}/x.db\nSENTINEL_ENV=production\nENABLE_DEMO_TARGET={demo}\n")
    env.chmod(0o600)
    result = subprocess.run(["bash", str(DEMO.parent / "scripts" / "run-local.sh"), "start", str(env)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode != 0 and "refused in production" in result.stderr
    assert not (tmp_path / "prod.env.run").exists()  # stopped before creating anything or opening ports
    assert "k" * 40 not in result.stdout + result.stderr


def test_source_scan_and_baselines_are_wired_into_existing_tabs_and_keyed_by_the_proxy():
    spec = importlib.util.spec_from_file_location("serve_routes_src", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in ("/api/source-apis", "/api/runtime/baselines"):
        assert module.KEYED_ROUTES["GET"].match(path) and not module.KEYED_ROUTES["POST"].match(path)
    for path in ("/api/source-scan", "/api/source-scan/upload"):
        assert module.KEYED_ROUTES["POST"].match(path) and not module.KEYED_ROUTES["GET"].match(path)
    for call in ('"/api/source-apis', '"/api/source-scan"', '"/api/source-scan/upload"', '"/api/runtime/baselines"'):
        assert call in JS, call
    discovery = INDEX.split('id="tab-discovery"')[1].split("</section>\n    </section>")[0]
    monitoring = INDEX.split('id="tab-monitoring"')[1].split('id="tab-detection"')[0]
    assert 'id="source-body"' in discovery and 'id="baselines-body"' in monitoring
    assert INDEX.count('data-tab="') == 9  # still nine tabs
    assert "project_root" not in JS  # the server-side path in the scan response is never shown


def test_investigation_and_endpoint_risk_are_read_only_keyed_routes_wired_into_existing_tabs():
    spec = importlib.util.spec_from_file_location("serve_routes_p5", DEMO / "serve.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for path in ("/api/alerts/12", "/api/incidents", "/api/risk/endpoints"):
        assert module.KEYED_ROUTES["GET"].match(path), path
        assert not module.KEYED_ROUTES["POST"].match(path)
    for path in ("/api/incidents", "/api/risk/endpoints"):  # PATCH /api/alerts/{id} is the existing triage
        assert not module.KEYED_ROUTES["PATCH"].match(path)
    assert not module.KEYED_ROUTES["GET"].match("/api/alerts/12/x")
    for call in ('"/api/alerts/" + encodeURIComponent(id)', '"/api/risk/endpoints"'):
        assert call in JS, call
    detection = INDEX.split('id="tab-detection"')[1].split('id="tab-risk"')[0]
    risk = INDEX.split('id="tab-risk"')[1].split('id="tab-proxy"')[0]
    assert 'id="detail-body"' in detection and 'id="alert-type"' in detection and 'id="alert-q"' in detection
    assert 'id="risk-body"' in risk and INDEX.count('data-tab="') == 9
    assert "flagged only, not blocked" in JS  # never implies blocking without a recorded decision
