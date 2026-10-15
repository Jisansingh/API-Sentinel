"""Static API route discovery. Source code is parsed/read, never imported or executed."""
from __future__ import annotations

import ast
import hashlib
import os
import re
import sqlite3
from pathlib import Path
from typing import Iterable

DEFAULT_EXTENSIONS = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".go", ".php", ".rb", ".cs"}
SKIP_DIRS = {".git", ".hg", ".svn", ".venv", "venv", "env", "__pycache__", "node_modules", "vendor", "dist", "build", "coverage", ".next", ".idea", ".vscode", "target", "bin", "obj"}
MAX_FILE_BYTES = 2 * 1024 * 1024
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE", "ANY"}

# Best-effort fallbacks for non-Python source. Python uses the AST scanner below.
PATTERNS = [
 (re.compile(r"\b(?:app|router|server|fastify|instance)\s*\.\s*(get|post|put|patch|delete|options|head|all)\s*\(\s*(['`\"])([^'`\"]+)\2", re.I), "js-route", "high"),
 (re.compile(r"\b(?:app|router)\s*\.\s*route\s*\(\s*(['`\"])([^'`\"]+)\1", re.I), "js-route-chain", "medium"),
 (re.compile(r"@(Get|Post|Put|Patch|Delete|Options|Head)\s*\(\s*(['\"]?)([^)'\"]*)\2\s*\)", re.I), "nestjs-decorator", "medium"),
 (re.compile(r"@(GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping|RequestMapping)\s*\(\s*(?:value\s*=\s*)?(['\"])(.*?)\2", re.I), "spring-mapping", "high"),
 (re.compile(r"\b\w+\s*\.\s*(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|Any)\s*\(\s*(['\"])(.*?)\2", re.I), "go-route", "high"),
 (re.compile(r"\bRoute\s*::\s*(get|post|put|patch|delete|options|any|match)\s*\(\s*(['\"])(.*?)\2", re.I), "laravel-route", "high"),
 (re.compile(r"^\s*(get|post|put|patch|delete)\s+(['\"])(.*?)\2", re.I | re.M), "rails-route", "medium"),
]

def _clean_path(value: str) -> str:
    value = value.strip().replace("\\/", "/")
    if not value: return "/"
    if not value.startswith("/"): value = "/" + value
    return re.sub(r"/{2,}", "/", value)

def _literal(node):
    try:
        value = ast.literal_eval(node)
        return value if isinstance(value, str) else None
    except (ValueError, TypeError):
        return None

def _python_routes(content: str) -> list[tuple[int, str, str, str, str]]:
    """Return line, method, path, detector, confidence for literal Python declarations."""
    try: tree = ast.parse(content)
    except (SyntaxError, ValueError): return []
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)): continue
        for dec in node.decorator_list:
            if not isinstance(dec, ast.Call): continue
            func = dec.func
            method_name = func.attr.lower() if isinstance(func, ast.Attribute) else ""
            receiver = func.value if isinstance(func, ast.Attribute) else None
            receiver_name = receiver.id.lower() if isinstance(receiver, ast.Name) else ""
            first = _literal(dec.args[0]) if dec.args else None
            if first is None: continue
            if method_name in {"get", "post", "put", "patch", "delete", "options", "head"}:
                found.append((dec.lineno, method_name.upper(), _clean_path(first), "python-decorator", "high"))
            elif method_name in {"route", "api_route"}:
                methods = []
                for kw in dec.keywords:
                    if kw.arg == "methods":
                        try: methods = [str(x).upper() for x in ast.literal_eval(kw.value) if isinstance(x, str)]
                        except (ValueError, TypeError): pass
                if not methods: methods = ["GET"]
                for method in methods:
                    if method in METHODS: found.append((dec.lineno, method, _clean_path(first), "python-route", "high" if method != "GET" or methods != ["GET"] else "medium"))
    # Django path()/re_path() declarations; method depends on the view implementation.
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name) or node.func.id not in {"path", "re_path"}: continue
        first = _literal(node.args[0]) if node.args else None
        if first is not None:
            found.append((node.lineno, "ANY", _clean_path(first), "django-" + node.func.id, "medium"))
    return list(dict.fromkeys(found))

def _non_python_routes(content: str, suffix: str) -> list[tuple[int, str, str, str, str]]:
    found=[]
    for pattern, detector, confidence in PATTERNS:
        for m in pattern.finditer(content):
            g=m.groups(); line=content.count("\n",0,m.start())+1
            if detector == "js-route": method,path=g[0].upper(),g[2]
            elif detector == "js-route-chain": method,path="ANY",g[1]
            elif detector == "nestjs-decorator": method,path=g[0].upper(),g[2].strip() or "/"
            elif detector == "spring-mapping": method,path={"getmapping":"GET","postmapping":"POST","putmapping":"PUT","patchmapping":"PATCH","deletemapping":"DELETE","requestmapping":"ANY"}.get(g[0].lower(),"ANY"),g[2]
            elif detector == "go-route": method,path=g[0].upper(),g[2]
            elif detector == "laravel-route": method,path=g[0].upper(),g[2]
            else: method,path=g[0].upper(),g[2]
            if method in {"ALL","ANY","MATCH"}: method="ANY"
            if path and not any(ch in path for ch in "\r\n"):
                found.append((line,method,_clean_path(path),detector,confidence))
    if suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        chain = re.compile(r"\b(?:app|router)\s*\.\s*route\s*\(\s*(['`\"])([^'`\"]+)\1\s*\)([^;\n]*)", re.I)
        method_pattern = re.compile(r"\.(get|post|put|patch|delete|options|head|all)\s*\(", re.I)
        for match in chain.finditer(content):
            line = content.count("\n", 0, match.start()) + 1
            methods = [m.upper() for m in method_pattern.findall(match.group(3))] or ["ANY"]
            for method in methods:
                found.append((line, "ANY" if method == "ALL" else method, _clean_path(match.group(2)), "js-route-chain", "medium"))
    return list(dict.fromkeys(found))

def _iter_source_files(root: Path, extensions: set[str]) -> Iterable[Path]:
    for current, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for filename in sorted(files):
            path=Path(current)/filename
            if path.is_symlink() or path.suffix.lower() not in extensions: continue
            try:
                if path.stat().st_size <= MAX_FILE_BYTES: yield path
            except OSError: continue

def ensure_source_schema(db_path: str | Path) -> None:
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("""CREATE TABLE IF NOT EXISTS source_code_apis (
          id INTEGER PRIMARY KEY AUTOINCREMENT, project_id TEXT NOT NULL,
          method TEXT NOT NULL, path TEXT NOT NULL, source_file TEXT NOT NULL,
          line_number INTEGER NOT NULL, detector TEXT NOT NULL, confidence TEXT NOT NULL,
          first_seen TEXT NOT NULL DEFAULT (datetime('now')), last_seen TEXT NOT NULL DEFAULT (datetime('now')),
          present_in_source INTEGER NOT NULL DEFAULT 1,
          UNIQUE(project_id, method, path, source_file, line_number, detector))""")
        conn.commit()

def scan_project(project_root: str | Path, db_path: str | Path, project_id: str | None = None, extensions: set[str] | None = None) -> dict:
    root=Path(project_root).expanduser().resolve()
    if not root.is_dir(): raise ValueError("project_root must be an existing directory")
    ext={x.lower() if x.startswith(".") else "."+x.lower() for x in (extensions or DEFAULT_EXTENSIONS)}
    project_id=project_id or hashlib.sha256(str(root).encode()).hexdigest()[:20]
    db=Path(db_path)
    if str(db_path) != ":memory:": db.parent.mkdir(parents=True,exist_ok=True)
    records={}; files_scanned=0; scan_errors=0
    for file_path in _iter_source_files(root,ext):
        try: content=file_path.read_text(encoding="utf-8",errors="replace")
        except OSError: scan_errors+=1; continue
        files_scanned+=1; relative=file_path.relative_to(root).as_posix(); suffix=file_path.suffix.lower()
        routes=_python_routes(content) if suffix == ".py" else _non_python_routes(content,suffix)
        for line,method,path,detector,confidence in routes:
            key=(project_id,method,path,relative,line,detector)
            records[key]={"project_id":project_id,"method":method,"path":path,"source_file":relative,"line_number":line,"detector":detector,"confidence":confidence}
    ensure_source_schema(db)
    with sqlite3.connect(str(db)) as conn:
        conn.execute("UPDATE source_code_apis SET present_in_source=0 WHERE project_id=?",(project_id,))
        for item in records.values():
            conn.execute("""INSERT INTO source_code_apis(project_id,method,path,source_file,line_number,detector,confidence,present_in_source,last_seen)
            VALUES(?,?,?,?,?,?,?,1,datetime('now')) ON CONFLICT(project_id,method,path,source_file,line_number,detector)
            DO UPDATE SET confidence=excluded.confidence,present_in_source=1,last_seen=datetime('now')""",
            (item["project_id"],item["method"],item["path"],item["source_file"],item["line_number"],item["detector"],item["confidence"]))
        conn.commit()
    return {"project_id":project_id,"project_root":str(root),"files_scanned":files_scanned,"routes_found":len(records),"scan_errors":scan_errors}

def list_source_apis(db_path: str | Path, project_id: str, include_absent: bool = False) -> list[dict]:
    ensure_source_schema(db_path)
    query="SELECT id,project_id,method,path,source_file,line_number,detector,confidence,first_seen,last_seen,present_in_source FROM source_code_apis WHERE project_id=?"
    if not include_absent: query += " AND present_in_source=1"
    query += " ORDER BY source_file,line_number,method,path"
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory=sqlite3.Row
        return [dict(row) for row in conn.execute(query,(project_id,)).fetchall()]
