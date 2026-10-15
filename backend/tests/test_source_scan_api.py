import io
import zipfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.routes import source_scan

KEY = "k" * 40


def _app(db_path, api_key=KEY):
    app = FastAPI()
    app.state.db_path = str(db_path)
    app.state.api_key = api_key.encode() if api_key else None
    app.include_router(source_scan.router)
    return app


def _zip_with_source():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("sample/app.py", '@app.get("/from-zip")\ndef route(): pass\n')
    return output.getvalue()


def test_zip_upload_requires_admin_key_and_stores_routes(tmp_path):
    app = _app(tmp_path / "sentinel.db")
    client = TestClient(app)
    payload = _zip_with_source()
    assert client.post("/api/source-scan/upload", content=payload, headers={"Content-Type": "application/zip"}).status_code == 401
    response = client.post("/api/source-scan/upload?project_id=zip-test", content=payload,
                           headers={"Content-Type": "application/zip", "X-Sentinel-Key": KEY})
    assert response.status_code == 200, response.text
    assert response.json()["routes_found"] == 1
    listed = client.get("/api/source-apis?project_id=zip-test", headers={"X-Sentinel-Key": KEY})
    assert listed.status_code == 200
    assert listed.json()["items"][0]["path"] == "/from-zip"


def test_zip_upload_rejects_path_traversal(tmp_path):
    app = _app(tmp_path / "sentinel.db")
    client = TestClient(app)
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../escape.py", '@app.get("/unsafe")\ndef x(): pass')
    response = client.post("/api/source-scan/upload", content=output.getvalue(),
                           headers={"Content-Type": "application/zip", "X-Sentinel-Key": KEY})
    assert response.status_code == 400


def test_github_url_validation_happens_before_network(tmp_path):
    app = _app(tmp_path / "sentinel.db")
    client = TestClient(app)
    response = client.post("/api/source-scan", json={"source_type":"github", "repo_url":"http://127.0.0.1/private"},
                           headers={"X-Sentinel-Key": KEY})
    assert response.status_code == 400


def test_local_directory_scan_respects_allow_list(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    project = allowed / "project"
    project.mkdir(parents=True)
    (project / "main.py").write_text('@app.post("/local-route")\ndef route(): pass\n', encoding="utf-8")
    monkeypatch.setenv("SENTINEL_SCAN_ROOTS", str(allowed))
    app = _app(tmp_path / "sentinel.db")
    client = TestClient(app)
    ok = client.post("/api/source-scan", json={"source_type":"local", "local_path":str(project), "project_id":"local-test"}, headers={"X-Sentinel-Key":KEY})
    assert ok.status_code == 200, ok.text
    assert ok.json()["items"][0]["path"] == "/local-route"
    denied = client.post("/api/source-scan", json={"source_type":"local", "local_path":str(tmp_path), "project_id":"outside"}, headers={"X-Sentinel-Key":KEY})
    assert denied.status_code == 400


def test_public_github_input_uses_safe_archive_pipeline(tmp_path, monkeypatch):
    monkeypatch.setattr(source_scan, "_download_public_github", lambda _url: (_zip_with_source(), "owner/repo"))
    app = _app(tmp_path / "sentinel.db")
    client = TestClient(app)
    response = client.post("/api/source-scan", json={"source_type":"github", "repo_url":"https://github.com/owner/repo", "project_id":"github-test"}, headers={"X-Sentinel-Key":KEY})
    assert response.status_code == 200, response.text
    assert response.json()["items"][0]["path"] == "/from-zip"
