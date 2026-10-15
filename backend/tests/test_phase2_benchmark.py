"""The labelled benchmark: reproducible, isolated, ground truth sane."""

import json
import os
import subprocess
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]


def _run(tmp_path, name):
    out = tmp_path / f"{name}.json"
    env = {k: v for k, v in os.environ.items() if not k.startswith("SENTINEL_")}
    env.update(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(BACKEND), DATABASE_URL="sqlite:///./must_not_exist.db")
    subprocess.run([sys.executable, "-m", "benchmark.run", "--json", str(out), "--markdown",
                    str(tmp_path / f"{name}.md")], cwd=tmp_path, env=env, check=True,
                   capture_output=True)
    return json.loads(out.read_text())


def test_benchmark_is_deterministic_isolated_and_complete(tmp_path):
    benchmark_link = tmp_path / "benchmark"
    try:
        benchmark_link.symlink_to(BACKEND / "benchmark", target_is_directory=True)  # cwd must not be backend/
    except (OSError, NotImplementedError):
        # Windows without Developer Mode/admin cannot create symlinks; copying
        # the deterministic benchmark package tests the same cwd isolation.
        import shutil
        shutil.copytree(BACKEND / "benchmark", benchmark_link)
    first, second = _run(tmp_path, "a"), _run(tmp_path, "b")
    for r in (first, second):
        r.pop("timings_not_deterministic")
    assert first == second                                   # identical metrics run to run
    assert not list(tmp_path.glob("*.db"))                   # never touched a database in cwd
    assert not list(BACKEND.glob("must_not_exist.db"))
    o = first["detection"]["overall"]
    assert o["tp"] + o["fp"] + o["tn"] + o["fn"] > 0
    assert first["dataset"]["synthetic"] is True
    assert first["scan"]["rescan_created"] == 0              # re-scan is idempotent
    shadow = first["shadow_api"]
    assert len(shadow["truth_undocumented"]) >= 2            # two genuine shadow endpoints
    assert shadow["recall"] == 1.0 and shadow["false_positives"] == []
    assert (tmp_path / "a.md").read_text().startswith("# API Sentinel benchmark")
