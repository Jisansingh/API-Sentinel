"""Evaluation: real accuracy numbers from the project's own labelled benchmark.

This does NOT invent a detection-accuracy metric. It runs the exact, already-tested
``backend/benchmark/run.py`` CLI (see ``tests/test_phase2_benchmark.py``) as an isolated
subprocess — same interpreter, its own temporary database, ground-truth-labelled
synthetic traffic through the real, unmodified capture -> analyze -> score -> alert
pipeline — and returns its JSON result. No detection, scoring or gateway logic is
touched or duplicated here; this route only exposes that existing, reproducible
evaluation over HTTP so the dashboard can show it instead of fabricating numbers.

``POST`` triggers a fresh run (a few seconds of CPU; gated like any other write) and,
only if it completes and its output validates, atomically saves it as the latest
result (``app/evaluation_store.py``: one JSON file outside the live database).
``GET`` returns that saved result, or ``available: false`` with an honest note when
nothing usable is stored. A failed, timed-out or malformed run never overwrites it.
One run at a time per process: a concurrent POST gets 409 instead of a second run.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError

from app import evaluation_store
from app.auth import require_read, require_write
from app.schemas import EvaluationResponse

router = APIRouter()

BACKEND_DIR = Path(__file__).resolve().parents[2]
DEFAULT_SEED = 20260105  # same default backend/benchmark/run.py uses
RUN_TIMEOUT_SECONDS = 60


def _not_run_yet(problem: str | None = None) -> EvaluationResponse:
    if problem:
        return EvaluationResponse(available=False, note=f"No usable evaluation result: {problem}. "
                                  "Run a new evaluation to replace it.")
    return EvaluationResponse(
        available=False,
        note="No evaluation has been run yet (no saved result). POST to run one (takes a few seconds; "
             "runs the project's own labelled benchmark in an isolated subprocess).",
    )


def run_benchmark_subprocess(seed: int, timeout: int = RUN_TIMEOUT_SECONDS) -> dict:
    """Invoke ``python -m benchmark.run`` exactly as its own test does: isolated cwd,
    a symlinked ``benchmark`` package, a filtered environment, a guaranteed-unused
    relative ``DATABASE_URL`` as a second safety net on top of the one the module sets
    for itself. Raises RuntimeError (generic, no path/stderr leakage past a short
    excerpt) or subprocess.TimeoutExpired."""
    with tempfile.TemporaryDirectory(prefix="sentinel-eval-") as work:
        (Path(work) / "benchmark").symlink_to(BACKEND_DIR / "benchmark")
        out = Path(work) / "result.json"
        env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
        env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(BACKEND_DIR),
                   DATABASE_URL="sqlite:///./must_not_exist.db")
        proc = subprocess.run(
            [sys.executable, "-m", "benchmark.run", "--seed", str(seed), "--json", str(out)],
            cwd=work, env=env, capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0 or not out.exists():
            raise RuntimeError(f"benchmark run exited {proc.returncode}: {proc.stderr[-400:].strip()}")
        return json.loads(out.read_text())


def _to_response(raw: dict, duration_ms: float, ran_at: str) -> EvaluationResponse:
    d = raw["detection"]

    def metrics(m):
        return {"tp": m["tp"], "fp": m["fp"], "tn": m["tn"], "fn": m["fn"], "precision": m["precision"],
                "recall": m["recall"], "f1": m["f1"], "false_positive_rate": m["false_positive_rate"]}

    scenarios = [{
        "name": name, "description": next(
            (s["description"] for s in raw["dataset"]["scenarios"] if s["name"] == name), ""),
        "holdout": next((s["holdout"] for s in raw["dataset"]["scenarios"] if s["name"] == name), False),
        "expected": row["expected"], "instances": row["instances"], "hits": row["hits"],
        "misses": row["misses"], "false_alerts": row["false_alerts"],
        "detection_rate": row["detection_rate"], "false_alert_rate": row["false_alert_rate"],
    } for name, row in d["per_scenario"].items()]
    return EvaluationResponse(
        available=True, note="Computed by actually running the labelled benchmark; see dataset/seed below.",
        ran_at=ran_at, duration_ms=duration_ms, seed=raw["dataset"]["seed"], synthetic=True,
        total_records=raw["dataset"]["records"], total_instances=raw["dataset"]["instances"],
        overall=metrics(d["overall"]), tuning_set=metrics(raw["detection_tuning_set"]["overall"]),
        holdout_set=metrics(raw["detection_holdout_set"]["overall"]),
        per_detection_type={t: metrics(m) for t, m in d["per_detection_type"].items()},
        scenarios=scenarios, shadow_api=raw["shadow_api"],
        unattributed_alerts=len(d["unattributed_alerts"]),
    )


@router.get("/api/evaluation", response_model=EvaluationResponse, dependencies=[Depends(require_read)])
def get_evaluation(request: Request) -> EvaluationResponse:
    """The latest saved successful run, or ``available: false``. Never runs one itself."""
    path = request.app.state.evaluation_path
    if path is None:  # in-memory database: nowhere durable to keep results
        cached = request.app.state.evaluation_cache
        return cached if cached is not None else _not_run_yet()
    result, problem = evaluation_store.load(path)
    return result if result is not None else _not_run_yet(problem)


@router.post("/api/evaluation", response_model=EvaluationResponse, dependencies=[Depends(require_write)])
def run_evaluation(request: Request) -> EvaluationResponse:
    """Run the labelled benchmark now (isolated subprocess, own temp database) and save the result."""
    lock = request.app.state.evaluation_lock
    if not lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="an evaluation run is already in progress")
    try:
        start = time.perf_counter()
        try:
            raw = run_benchmark_subprocess(DEFAULT_SEED)
        except subprocess.TimeoutExpired:
            raise HTTPException(status_code=504, detail="evaluation run timed out") from None
        except (RuntimeError, OSError, json.JSONDecodeError):
            raise HTTPException(status_code=502, detail="evaluation run failed") from None
        duration_ms = round((time.perf_counter() - start) * 1000, 1)
        try:
            result = _to_response(raw, duration_ms=duration_ms, ran_at=request.app.state.clock().isoformat())
        except (KeyError, TypeError, ValueError, ValidationError):
            raise HTTPException(status_code=502, detail="evaluation output was malformed") from None
        path = request.app.state.evaluation_path
        if path is None:
            request.app.state.evaluation_cache = result
            result.persisted = False
            result.note += " Not saved: the backend uses an in-memory database, so results last until restart."
            return result
        result.persisted = True
        try:
            evaluation_store.save(path, result)
        except OSError as err:
            result.persisted = False
            result.note += (f" Not saved ({type(err).__name__}): the previous saved result, if any, is unchanged. "
                            "Check that the evaluation results location is writable.")
        return result
    finally:
        lock.release()
