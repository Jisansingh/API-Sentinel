"""Optional retention: dry run by default, explicit apply, protected alert states."""

import sqlite3
from datetime import timedelta

import pytest

from app.maintenance import main, prune
from app.storage import init_db
from app.timeutil import utcnow


def _db(tmp_path):
    db = str(tmp_path / "m.db")
    init_db(db)
    now = utcnow()
    with sqlite3.connect(db) as conn:
        for days in (1, 10, 100):
            conn.execute("INSERT INTO captured_requests (method, path, status_code, duration_ms, client_ip,"
                         " created_at) VALUES ('GET', '/a', 200, 1, 't', ?)",
                         ((now - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S"),))
        for status in ("open", "acknowledged", "resolved", "ignored"):
            conn.execute("INSERT INTO alerts (detection_type, actor, endpoint, risk_score, reason, status,"
                         " first_seen, last_seen) VALUES ('scraping', ?, '/e', 30, 'r', ?, ?, ?)",
                         (status, status, (now - timedelta(days=200)).isoformat(),
                          (now - timedelta(days=200)).isoformat()))
    return db


def _counts(db):
    with sqlite3.connect(db) as conn:
        return (conn.execute("SELECT COUNT(*) FROM captured_requests").fetchone()[0],
                conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0])


def test_dry_run_reports_but_deletes_nothing(tmp_path):
    db = _db(tmp_path)
    result = prune(db, captures_days=30, alerts_days=90)
    assert result == {"applied": False, "captures_deleted": 1, "alerts_deleted": 2}
    assert _counts(db) == (3, 4)


def test_apply_deletes_only_expired_rows_and_keeps_open_alerts(tmp_path):
    db = _db(tmp_path)
    prune(db, captures_days=30, alerts_days=90, apply=True)
    assert _counts(db) == (2, 2)
    with sqlite3.connect(db) as conn:
        assert {r[0] for r in conn.execute("SELECT status FROM alerts")} == {"open", "acknowledged"}


def test_backup_is_written_first_and_never_overwritten(tmp_path):
    db = _db(tmp_path)
    backup = tmp_path / "pre.db"
    prune(db, captures_days=30, apply=True, backup_to=backup)
    assert _counts(str(backup)) == (3, 4)
    with pytest.raises(ValueError, match="already exists"):
        prune(db, captures_days=1, apply=True, backup_to=backup)
    assert _counts(db)[0] == 2  # failed backup => nothing more was deleted


def test_invalid_inputs_are_rejected(tmp_path):
    with pytest.raises(ValueError):
        prune(tmp_path / "nope.db", captures_days=1)
    with pytest.raises(ValueError):
        prune(_db(tmp_path), captures_days=0)


def test_cli_dry_run_by_default(tmp_path, capsys):
    db = _db(tmp_path)
    assert main(["--db", db, "--captures-days", "30"]) == 0
    assert "dry run" in capsys.readouterr().out and _counts(db) == (3, 4)
    assert main(["--db", str(tmp_path / "missing.db"), "--captures-days", "30"]) == 2


def test_access_control_events_are_pruned_only_when_asked(tmp_path):
    from app.storage import save_gateway_event

    db = _db(tmp_path)
    now = utcnow()
    for days in (1, 40):
        ts = (now - timedelta(days=days)).isoformat(timespec="seconds")
        save_gateway_event(db, window_start=ts, seen_at=ts, endpoint="GET /api/health",
                           decision="rate_limited", reason="quota_exceeded", status_code=429,
                           identity_kind="ip", client_ip="203.0.113.1")
    assert "events_deleted" not in prune(db, captures_days=30)
    assert prune(db, events_days=30) == {"applied": False, "captures_deleted": 0,
                                        "alerts_deleted": 0, "events_deleted": 1}
    prune(db, events_days=30, apply=True)
    with sqlite3.connect(db) as conn:
        assert conn.execute("SELECT COUNT(*) FROM gateway_events").fetchone()[0] == 1
