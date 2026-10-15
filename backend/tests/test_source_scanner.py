from app.source_scanner import list_source_apis, scan_project


def test_scans_python_ast_and_javascript_routes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "main.py").write_text(
        'from fastapi import FastAPI\napp = FastAPI()\n'
        '@app.get("/users/{user_id}")\ndef get_user(user_id: int): pass\n'
        '@router.route("/users", methods=["GET", "POST"])\ndef users(): pass\n'
        'path("orders/", view)\n', encoding="utf-8"
    )
    (project / "routes.ts").write_text(
        "app.delete('/users/:id', handler);\n"
        "router.route('/orders').get(handler).post(handler);\n", encoding="utf-8"
    )
    db = tmp_path / "sentinel.db"
    summary = scan_project(project, db, project_id="test-project")
    routes = list_source_apis(db, "test-project")
    pairs = {(r["method"], r["path"]) for r in routes}
    assert summary["files_scanned"] == 2
    assert ("GET", "/users/{user_id}") in pairs
    assert ("GET", "/users") in pairs and ("POST", "/users") in pairs
    assert ("ANY", "/orders/") in pairs
    assert ("DELETE", "/users/:id") in pairs
    assert ("GET", "/orders") in pairs and ("POST", "/orders") in pairs
    assert all(r["source_file"] and r["line_number"] > 0 for r in routes)


def test_scan_marks_removed_routes_absent(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    source = project / "app.py"
    source.write_text('@app.get("/old")\ndef old(): pass\n', encoding="utf-8")
    db = tmp_path / "sentinel.db"
    scan_project(project, db, project_id="p")
    source.write_text('@app.get("/new")\ndef new(): pass\n', encoding="utf-8")
    scan_project(project, db, project_id="p")
    assert {r["path"] for r in list_source_apis(db, "p")} == {"/new"}
    all_rows = list_source_apis(db, "p", include_absent=True)
    assert any(r["path"] == "/old" and r["present_in_source"] == 0 for r in all_rows)


def test_never_scans_dependency_directories_or_large_files(tmp_path):
    project = tmp_path / "project"
    (project / "node_modules").mkdir(parents=True)
    (project / "node_modules" / "ignored.py").write_text('@app.get("/bad")\ndef x(): pass')
    (project / "huge.py").write_bytes(b"#" * (2 * 1024 * 1024 + 1))
    (project / "safe.py").write_text('@app.post("/safe")\ndef x(): pass')
    result = scan_project(project, tmp_path / "db.sqlite", project_id="safe")
    assert result["files_scanned"] == 1
    assert result["routes_found"] == 1
