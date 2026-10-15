"""Dashboard files and proxy hardening: static allowlist, security headers,
no key in any served file, no unsafe DOM insertion, JS wiring matches the HTML."""

import importlib.util
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
