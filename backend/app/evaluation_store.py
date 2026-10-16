"""Durable storage for the latest successful evaluation result (one small JSON file).

Deliberately separate from the live security database: evaluation results are
synthetic-benchmark metrics, not captured traffic or alerts, and must never share
a file (or a write lock) with them.

Location: ``SENTINEL_EVALUATION_PATH`` if set, otherwise ``evaluation-latest.json``
next to the configured SQLite file (an in-memory database has no file, so results
then stay in memory only). Clear results intentionally by deleting that file.

Writes are atomic (temp file in the same directory, fsync, ``os.replace``) and the
file is created with mode 0600. Only a result from a completed, successful
benchmark run is ever passed to ``save``; nothing here invents or repairs data.
"""

import json
import os
import tempfile
from pathlib import Path

from pydantic import ValidationError

from app.schemas import EvaluationResponse

FILE_NAME = "evaluation-latest.json"
FORMAT_VERSION = 1


def default_path(db_path: str) -> Path | None:
    if db_path == ":memory:":
        return None
    return Path(db_path).resolve().parent / FILE_NAME


def resolve_path(explicit: str | None, db_path: str) -> Path | None:
    path = Path(explicit).resolve() if explicit else default_path(db_path)
    if path is not None and db_path != ":memory:" and path == Path(db_path).resolve():
        raise ValueError("the evaluation results file must not be the security database")
    return path


def load(path: Path | None) -> tuple[EvaluationResponse | None, str | None]:
    """(result, problem). Missing file = (None, None): simply nothing stored yet."""
    if path is None or not path.exists():
        return None, None
    try:
        raw = json.loads(path.read_text())
    except OSError as err:
        return None, f"stored evaluation result could not be read ({type(err).__name__})"
    except ValueError:
        return None, "stored evaluation result is malformed (not valid JSON)"
    if not isinstance(raw, dict) or raw.get("format") != FORMAT_VERSION or not isinstance(raw.get("result"), dict):
        return None, "stored evaluation result has an unexpected format"
    try:
        result = EvaluationResponse.model_validate(raw["result"])
    except ValidationError:
        return None, "stored evaluation result failed validation"
    if not result.available or result.overall is None:
        return None, "stored evaluation result is incomplete"
    return result, None


def save(path: Path, result: EvaluationResponse) -> None:
    """Atomically replace the stored result. Raises OSError on failure (old file intact)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"format": FORMAT_VERSION, "result": result.model_dump(mode="json")},
                         indent=1, sort_keys=True)
    fd, tmp = tempfile.mkstemp(prefix=".evaluation-", suffix=".tmp", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
