"""Protection-status classification in the dashboard, fed with REAL backend responses.

The pure block between ``protection-state:start`` / ``:end`` in demo/dashboard.js is run
in Node against /api/rate-limits + /api/gateway-events payloads produced by real app
instances (gateway off, gateway on with no failures, gateway on with a real upstream
refusal), so the UI state is tied to what the backend actually reports.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.gateway as gw
from app.main import create_app

DEMO = Path(__file__).resolve().parents[2] / "demo"
JS = (DEMO / "dashboard.js").read_text()
KEY = "k" * 40
ROUTES = [{"method": "GET", "path": "/a", "auth": "none"}]

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")


def _block():
    m = re.search(r"/\* protection-state:start.*?\*/(.*?)/\* protection-state:end \*/", JS, re.S)
    assert m, "protection-state block markers missing from dashboard.js"
    return m.group(1)


def classify(access):
    script = _block() + "\nconst a = JSON.parse(process.argv[1]);\n" \
        "console.log(JSON.stringify({p: protectionState(a), r: rateLimitState(a), e: eventSummary(a)}));"
    out = subprocess.run(["node", "-e", script, json.dumps(access)], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


def _access(client):
    h = {"X-Sentinel-Key": KEY}
    return {"limits": client.get("/api/rate-limits", headers=h).json(),
            "events": client.get("/api/gateway-events", params={"limit": 100}, headers=h).json()}


def test_unknown_when_access_data_is_missing():
    for access in (None, {}, {"limits": None, "events": None}):
        r = classify(access)
        assert r["p"]["key"] == "unknown" and r["r"]["key"] == "unknown"
        assert r["e"] == "Access-control events unavailable."


def test_disabled_from_a_real_backend_without_gateway(tmp_path):
    r = classify(_access(TestClient(create_app(db_path=str(tmp_path / "x.db"), api_key=KEY))))
    assert r["p"]["key"] == "disabled" and r["p"]["kind"] == "info"
    assert "not a fault" in r["p"]["detail"]
    assert r["r"]["key"] == "configured" and "endpoints with a quota" in r["r"]["label"]
    assert "does not mean attacks were blocked" in r["e"]


def test_configured_but_unverified_never_claims_active(tmp_path):
    app = create_app(db_path=str(tmp_path / "x.db"), api_key=KEY,
                     gateway={"upstream": "http://127.0.0.1:9", "allow_private_network": True, "routes": ROUTES})
    r = classify(_access(TestClient(app)))
    assert r["p"]["key"] == "configured_unverified" and r["p"]["kind"] == "warn"
    assert "cannot confirm" in r["p"]["detail"]


def test_configured_with_real_upstream_failure_events(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "resolve_host", lambda host, port: ["169.254.169.254"])
    app = create_app(db_path=str(tmp_path / "x.db"), api_key=KEY,
                     gateway={"upstream": "http://upstream.internal", "allow_private_network": True,
                              "routes": ROUTES})
    c = TestClient(app)
    assert c.get("/gateway/a").status_code == 502 and c.get("/gateway/a").status_code == 502
    r = classify(_access(c))
    assert r["p"]["key"] == "configured_errors" and r["p"]["kind"] == "bad"
    assert r["p"]["failures"] == 2 and r["p"]["lastFailure"]
    assert "2 recorded requests" in r["e"]


def test_no_state_is_ever_green_and_no_active_state_exists():
    block = _block()
    assert 'kind: "ok"' not in block
    assert "configured_errors" in block and "configured_unverified" in block and "disabled" in block
    assert '"active"' not in block


def test_failure_reasons_match_the_gateways_real_reason_codes():
    js = set(re.findall(r'"((?:upstream_[a-z_]+)|response_too_large)"', _block()))
    backend = set(re.findall(r'"((?:upstream_[a-z_]+)|response_too_large)"',
                             (Path(gw.__file__)).read_text()))
    assert js == backend and len(js) == 5


def test_banner_is_rendered_in_overview_and_proxy_tabs():
    assert 'id="overview-protection"' in (DEMO / "index.html").read_text()
    assert 'setBody("overview-protection", protectionBanner(acc));' in JS
    assert "const facts = protectionBanner(acc);" in JS
