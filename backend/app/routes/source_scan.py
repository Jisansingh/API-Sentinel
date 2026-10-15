"""Authenticated source-code scanning endpoints.

Source is never imported or executed. GitHub archives and uploaded ZIP files are
validated and extracted into temporary directories before static scanning.
"""
from __future__ import annotations

import io
import json
import os
import re
import stat
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.auth import require_read, require_write
from app.source_scanner import list_source_apis, scan_project

router = APIRouter()
MAX_ARCHIVE_BYTES = 20 * 1024 * 1024
MAX_EXPANDED_BYTES = 80 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 5000
ALLOWED_GITHUB_HOSTS = {"github.com", "api.github.com", "codeload.github.com"}
PROJECT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class SourceScanRequest(BaseModel):
    source_type: Literal["github", "local"]
    project_id: str | None = Field(default=None, min_length=1, max_length=100)
    repo_url: str | None = Field(default=None, max_length=2048)
    local_path: str | None = Field(default=None, max_length=4096)


def _project_id(value: str | None, fallback: str) -> str:
    result = (value or fallback).strip()
    if not PROJECT_ID_RE.fullmatch(result):
        raise HTTPException(status_code=422, detail="project_id may contain only letters, numbers, dots, underscores, and hyphens")
    return result


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Only follow HTTPS redirects to known GitHub archive/API hosts."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or parsed.hostname not in ALLOWED_GITHUB_HOSTS:
            raise HTTPException(status_code=400, detail="GitHub archive redirected to an unsupported host")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _github_request(url: str, accept: str) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_GITHUB_HOSTS or parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Only public GitHub repository URLs are supported")
    opener = urllib.request.build_opener(_SafeRedirect())
    request = urllib.request.Request(url, headers={"User-Agent": "API-Sentinel-Source-Scanner/1.0", "Accept": accept})
    try:
        with opener.open(request, timeout=12) as response:
            final = urllib.parse.urlparse(response.geturl())
            if final.scheme != "https" or final.hostname not in ALLOWED_GITHUB_HOSTS:
                raise HTTPException(status_code=400, detail="GitHub response host is not allowed")
            data = response.read(MAX_ARCHIVE_BYTES + 1)
    except HTTPException:
        raise
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"Unable to retrieve public GitHub repository ({type(exc).__name__})") from None
    if len(data) > MAX_ARCHIVE_BYTES:
        raise HTTPException(status_code=413, detail="GitHub archive exceeds the 20 MiB download limit")
    return data


def _download_public_github(repo_url: str) -> tuple[bytes, str]:
    parsed = urllib.parse.urlparse(repo_url)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HTTPException(status_code=400, detail="Use a public https://github.com/owner/repository URL")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) != 2 or any(p in {".", ".."} for p in parts):
        raise HTTPException(status_code=400, detail="Repository URL must contain exactly owner and repository")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo or not re.fullmatch(r"[A-Za-z0-9_.-]+", owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", repo):
        raise HTTPException(status_code=400, detail="Invalid GitHub owner or repository name")
    api_url = f"https://api.github.com/repos/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}"
    try:
        metadata = json.loads(_github_request(api_url, "application/vnd.github+json"))
    except (ValueError, TypeError):
        raise HTTPException(status_code=502, detail="GitHub returned invalid repository metadata") from None
    if metadata.get("private") is True or not isinstance(metadata.get("default_branch"), str):
        raise HTTPException(status_code=400, detail="Repository must be public and have a default branch")
    branch = metadata["default_branch"]
    archive_url = f"https://codeload.github.com/{urllib.parse.quote(owner)}/{urllib.parse.quote(repo)}/zip/refs/heads/{urllib.parse.quote(branch, safe='')}"
    return _github_request(archive_url, "application/zip"), f"{owner}/{repo}"


def _extract_validated_zip(payload: bytes, destination: Path) -> Path:
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise HTTPException(status_code=413, detail="ZIP upload exceeds the 20 MiB limit")
    try:
        archive = zipfile.ZipFile(io.BytesIO(payload))
    except (zipfile.BadZipFile, OSError):
        raise HTTPException(status_code=400, detail="Upload must be a valid ZIP archive") from None
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_MEMBERS:
            raise HTTPException(status_code=413, detail="ZIP contains too many files")
        total = 0
        root = destination.resolve()
        for info in infos:
            name = info.filename.replace("\\", "/")
            pure = PurePosixPath(name)
            mode = info.external_attr >> 16
            if not name or pure.is_absolute() or any(part in {"..", ""} for part in pure.parts) or "\x00" in name or re.match(r"^[A-Za-z]:", name):
                raise HTTPException(status_code=400, detail="ZIP contains an unsafe path")
            file_type = stat.S_IFMT(mode)
            if stat.S_ISLNK(mode) or (file_type and file_type not in {stat.S_IFREG, stat.S_IFDIR}):
                raise HTTPException(status_code=400, detail="ZIP contains a symbolic link or special file")
            total += info.file_size
            if total > MAX_EXPANDED_BYTES:
                raise HTTPException(status_code=413, detail="ZIP expanded contents exceed the 80 MiB limit")
            target = (root / Path(*pure.parts)).resolve()
            if not target.is_relative_to(root):
                raise HTTPException(status_code=400, detail="ZIP contains an unsafe path")
        # Extract only after every member has passed validation.
        for info in infos:
            pure = PurePosixPath(info.filename.replace("\\", "/"))
            target = root / Path(*pure.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    output.write(chunk)
        # GitHub ZIPs wrap the project in a single generated directory.
        children = list(root.iterdir())
        if len(children) == 1 and children[0].is_dir():
            return children[0]
        return root


def _allowed_local_path(value: str) -> Path:
    raw_roots = os.getenv("SENTINEL_SCAN_ROOTS", "")
    roots = [Path(part).expanduser().resolve() for part in raw_roots.split(os.pathsep) if part.strip()]
    if not roots:
        raise HTTPException(status_code=400, detail="Local scanning is disabled; configure SENTINEL_SCAN_ROOTS")
    try:
        target = Path(value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        raise HTTPException(status_code=400, detail="Local project directory does not exist") from None
    if not target.is_dir() or not any(target.is_relative_to(root) for root in roots):
        raise HTTPException(status_code=400, detail="Local project path is outside configured SENTINEL_SCAN_ROOTS")
    return target


@router.post("/api/source-scan", dependencies=[Depends(require_write)])
def start_source_scan(body: SourceScanRequest, request: Request) -> dict:
    """Scan a public GitHub repository or an allow-listed local source tree."""
    db_path = request.app.state.db_path
    if body.source_type == "local":
        if not body.local_path:
            raise HTTPException(status_code=422, detail="local_path is required for local scans")
        root = _allowed_local_path(body.local_path)
        project_id = _project_id(body.project_id, root.name)
        summary = scan_project(root, db_path, project_id=project_id)
        return {**summary, "source_type": "local", "items": list_source_apis(db_path, project_id)}
    if not body.repo_url:
        raise HTTPException(status_code=422, detail="repo_url is required for GitHub scans")
    payload, repository = _download_public_github(body.repo_url)
    project_id = _project_id(body.project_id, repository.replace("/", "-"))
    with tempfile.TemporaryDirectory(prefix="sentinel-source-") as tmp:
        root = _extract_validated_zip(payload, Path(tmp))
        summary = scan_project(root, db_path, project_id=project_id)
    return {**summary, "source_type": "github", "repository": repository, "items": list_source_apis(db_path, project_id)}


@router.post("/api/source-scan/upload", dependencies=[Depends(require_write)])
async def upload_source_zip(request: Request, project_id: str = Query(default="uploaded-project", min_length=1, max_length=100)) -> dict:
    """Scan raw ZIP request bytes (Content-Type: application/zip)."""
    project_id = _project_id(project_id, "uploaded-project")
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_ARCHIVE_BYTES:
                raise HTTPException(status_code=413, detail="ZIP upload exceeds the 20 MiB limit")
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid Content-Length") from None
    payload = await request.body()
    if len(payload) > MAX_ARCHIVE_BYTES:
        raise HTTPException(status_code=413, detail="ZIP upload exceeds the 20 MiB limit")
    with tempfile.TemporaryDirectory(prefix="sentinel-upload-") as tmp:
        root = _extract_validated_zip(payload, Path(tmp))
        summary = scan_project(root, request.app.state.db_path, project_id=project_id)
    return {**summary, "source_type": "upload", "items": list_source_apis(request.app.state.db_path, project_id)}


@router.get("/api/source-apis", dependencies=[Depends(require_read)])
def get_source_apis(request: Request, project_id: str = Query(min_length=1, max_length=100), include_absent: bool = False) -> dict:
    """List source-discovered API declarations for a project."""
    project_id = _project_id(project_id, "")
    return {"project_id": project_id, "items": list_source_apis(request.app.state.db_path, project_id, include_absent)}
