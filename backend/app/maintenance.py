"""Optional, explicit retention for old captured traffic and alerts.

Nothing in Sentinel deletes data on its own. This command reports what would
be removed (dry run, the default) and only deletes with ``--apply``:

    python3 -m app.maintenance --db ./api_sentinel.db --captures-days 30 --alerts-days 90
    python3 -m app.maintenance --db ./api_sentinel.db --captures-days 30 --apply --backup-to ./pre-prune.db

- captured requests: rows older than ``--captures-days`` (by ``created_at``).
- alerts: only ``resolved`` or ``ignored`` alerts whose ``last_seen`` is older
  than ``--alerts-days``. Open and acknowledged alerts are never pruned.
``--backup-to`` writes a consistent SQLite copy first (refuses to overwrite).
"""

import argparse
import sqlite3
import sys
from datetime import timedelta
from pathlib import Path

from app.timeutil import utcnow

PRUNABLE_ALERT_STATUSES = ("resolved", "ignored")


def _cutoff(days: int) -> str:
    return (utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")


def prune(
    db_path: str | Path,
    *,
    captures_days: int | None = None,
    alerts_days: int | None = None,
    apply: bool = False,
    backup_to: str | Path | None = None,
) -> dict:
    """Count (and with ``apply`` delete) expired rows. Returns the counts."""
    path = Path(db_path)
    if str(db_path) == ":memory:" or not path.is_file():
        raise ValueError("database file not found")
    for days in (captures_days, alerts_days):
        if days is not None and days < 1:
            raise ValueError("retention periods must be at least 1 day")
    result = {"applied": apply, "captures_deleted": 0, "alerts_deleted": 0}
    with sqlite3.connect(str(path)) as conn:
        queries = []
        if captures_days is not None:
            queries.append(("captures_deleted", "captured_requests", "created_at < ?",
                            (_cutoff(captures_days),)))
        if alerts_days is not None:
            marks = ",".join("?" * len(PRUNABLE_ALERT_STATUSES))
            queries.append(("alerts_deleted", "alerts",
                            f"status IN ({marks}) AND replace(last_seen, 'T', ' ') < ?",
                            (*PRUNABLE_ALERT_STATUSES, _cutoff(alerts_days))))
        for key, table, where, params in queries:
            result[key] = conn.execute(f"SELECT COUNT(*) FROM {table} WHERE {where}", params).fetchone()[0]
        if apply and any(result[k] for k in ("captures_deleted", "alerts_deleted")):
            if backup_to:
                target = Path(backup_to)
                if target.exists():
                    raise ValueError("backup target already exists; refusing to overwrite")
                with sqlite3.connect(str(target)) as dest:
                    conn.backup(dest)
            for key, table, where, params in queries:
                conn.execute(f"DELETE FROM {table} WHERE {where}", params)
            conn.commit()
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", required=True)
    ap.add_argument("--captures-days", type=int)
    ap.add_argument("--alerts-days", type=int)
    ap.add_argument("--apply", action="store_true", help="actually delete (default: dry run)")
    ap.add_argument("--backup-to", help="copy the database here before deleting")
    args = ap.parse_args(argv)
    if args.captures_days is None and args.alerts_days is None:
        ap.error("give --captures-days and/or --alerts-days")
    try:
        result = prune(args.db, captures_days=args.captures_days, alerts_days=args.alerts_days,
                       apply=args.apply, backup_to=args.backup_to)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    verb = "deleted" if args.apply else "would delete (dry run, use --apply)"
    print(f"{verb}: {result['captures_deleted']} captured requests, {result['alerts_deleted']} alerts")
    return 0


if __name__ == "__main__":
    sys.exit(main())
