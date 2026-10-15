"""Run the labelled benchmark against an isolated database.

    cd backend
    python3 -m benchmark.run --json out/bench.json --markdown out/bench.md

Everything happens in a temporary directory: no live database, no network, no
real secrets. The same scenarios run unchanged against any version of the
``app`` package on ``sys.path`` (it adapts to older ``create_app`` signatures),
so a baseline can be measured on an older checkout with the same command.
Metrics describe SYNTHETIC scenarios only, not real-world performance.
"""

import argparse
import inspect
import json
import os
import platform
import sqlite3
import statistics
import sys
import tempfile
import time
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="sentinel-bench-")
# Set BEFORE importing app: guards against any import-time database creation.
os.environ["DATABASE_URL"] = f"sqlite:///{_TMP}/import-guard.db"
for _var in ("SENTINEL_API_KEY", "SENTINEL_FP_SECRET", "ENABLE_DEMO_TARGET", "OPENAPI_SPEC_PATH",
             "SENTINEL_ENV"):
    os.environ.pop(_var, None)

from fastapi.testclient import TestClient  # noqa: E402

from app.analysis import analyze_captured_traffic  # noqa: E402
from app.capture import credential_fingerprint  # noqa: E402
from app.main import create_app  # noqa: E402
from app.storage import init_db  # noqa: E402
from benchmark import scenarios as sc  # noqa: E402


def _fp(token):
    return credential_fingerprint({"authorization": f"Bearer {token}"}, sc.BENCH_FP_SECRET.encode())


def _load(db_path, records):
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        for r in records:
            conn.execute(
                "INSERT INTO captured_requests"
                " (method, path, status_code, duration_ms, client_ip, created_at, actor_fp)"
                " VALUES (?, ?, ?, 1.0, ?, ?, ?)",
                (r["method"], r["path"], r["status"], r["ip"],
                 r["t"].strftime("%Y-%m-%d %H:%M:%S"), _fp(r["token"]) if r["token"] else None),
            )


def _ids(alert):
    md = alert.get("metadata") or {}
    ids = {str(alert.get("actor"))}
    for key in ("client_ip", "actor", "token_fingerprint"):
        if md.get(key):
            ids.add(str(md[key]))
    ids.update(str(ip) for ip in md.get("ips", []))
    return ids


def _ratio(num, den):
    return round(num / den, 4) if den else None


def _metrics(tp, fp, tn, fn):
    p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * p * r / (p + r), 4) if p and r else (0.0 if p is not None and r is not None else None)
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": p, "recall": r, "f1": f1,
            "false_positive_rate": _ratio(fp, fp + tn)}


def evaluate(alerts, instances, holdout=None):
    """Confusion matrices. ``holdout`` None = all scenarios, else only that split."""
    scen = {s.name: s for s in sc.SCENARIOS}
    fp_to_inst = {}
    ip_to_inst = {}
    for inst in instances:
        for tok in inst.tokens:
            fp_to_inst[_fp(tok)] = inst
        for ip in inst.ips:
            ip_to_inst[ip] = inst
    found = {}  # (scenario, index) -> set of detection types
    unattributed = []
    for a in alerts:
        inst = next((fp_to_inst.get(i) or ip_to_inst.get(i) for i in _ids(a)
                     if fp_to_inst.get(i) or ip_to_inst.get(i)), None)
        if inst is None:
            unattributed.append({"type": a["detection_type"], "actor": a["actor"][:12],
                                 "endpoint": a["endpoint"]})
            continue
        found.setdefault((inst.scenario, inst.index), set()).add(a["detection_type"])

    cells = {t: [0, 0, 0, 0] for t in sc.DETECTION_TYPES}  # tp, fp, tn, fn
    per_scenario = {}
    for inst in instances:
        s = scen[inst.scenario]
        if holdout is not None and s.holdout != holdout:
            continue
        pred = found.get((inst.scenario, inst.index), set())
        row = per_scenario.setdefault(s.name, {"instances": 0, "expected": sorted(s.expected),
                                               "hits": 0, "misses": 0, "false_alerts": 0,
                                               "instances_with_false_alert": 0})
        row["instances"] += 1
        spurious = 0
        for t in sc.DETECTION_TYPES:
            if t in s.tolerated and t not in s.expected:
                continue
            truth, got = t in s.expected, t in pred
            idx = 0 if truth and got else 1 if got else 3 if truth else 2
            cells[t][idx] += 1
            row["hits"] += truth and got
            row["misses"] += truth and not got
            spurious += got and not truth
        row["false_alerts"] += spurious
        row["instances_with_false_alert"] += bool(spurious)
    for row in per_scenario.values():
        total_expected = len(row["expected"]) * row["instances"]
        row["detection_rate"] = _ratio(row["hits"], total_expected) if total_expected else None
        row["false_alert_rate"] = _ratio(row["instances_with_false_alert"], row["instances"])
    tot = [sum(c[i] for c in cells.values()) for i in range(4)]
    if holdout is None:
        tot[1] += len(unattributed)  # alerts that match no labelled actor are false positives
    return {
        "overall": _metrics(*tot),
        "per_detection_type": {t: _metrics(*c) for t, c in cells.items()},
        "per_scenario": per_scenario,
        "unattributed_alerts": unattributed,
    }


def evaluate_shadow(shadow_json):
    predicted = {(r["method"], r["path"]) for r in shadow_json["shadow_apis"]}
    tp = predicted & sc.UNDOCUMENTED_TRUTH
    out = {
        "spec_loaded": shadow_json["spec_loaded"],
        "truth_undocumented": sorted(map(list, sc.UNDOCUMENTED_TRUTH)),
        "predicted_shadow": sorted(map(list, predicted)),
        "false_positives": sorted(map(list, predicted - sc.UNDOCUMENTED_TRUTH)),
        "missed": sorted(map(list, sc.UNDOCUMENTED_TRUTH - predicted)),
        "documented_reported": len(shadow_json["documented"]),
        "precision": _ratio(len(tp), len(predicted)),
        "recall": _ratio(len(tp), len(sc.UNDOCUMENTED_TRUTH)),
    }
    return out


def run(seed):
    records, instances = sc.build(seed)
    work = Path(_TMP)
    db_path = str(work / "bench.db")
    _load(db_path, records)
    spec_path = work / "spec.json"
    spec_path.write_text(json.dumps(sc.SPEC))

    wanted = {"db_path": db_path, "fp_secret": sc.BENCH_FP_SECRET, "api_key": sc.BENCH_API_KEY,
              "enable_capture": False, "spec_dir": str(work)}
    params = inspect.signature(create_app).parameters
    if "ownership" in params:
        wanted["ownership"] = sc.ownership_context(_fp)
    app = create_app(**{k: v for k, v in wanted.items() if k in params})
    client = TestClient(app, headers={"X-Sentinel-Key": sc.BENCH_API_KEY})

    timings = {}

    def timed(label, fn, repeat=5):
        runs = []
        for _ in range(repeat):
            t = time.perf_counter()
            result = fn()
            runs.append((time.perf_counter() - t) * 1000)
        timings[label] = {"median_ms": round(statistics.median(runs), 2), "max_ms": round(max(runs), 2)}
        return result

    first = client.post("/api/scan")
    assert first.status_code == 200, first.text
    scan_counts = first.json()
    timed("scan_ms", lambda: client.post("/api/scan"))
    rescan = client.post("/api/scan").json()
    alerts = client.get("/api/alerts").json()["items"]
    shadow = timed("shadow_apis_ms", lambda: client.get(
        "/api/shadow-apis", params={"spec_path": str(spec_path)}).json())
    timed("analysis_only_ms", lambda: analyze_captured_traffic(
        [{"method": r["method"], "path": r["path"], "status_code": r["status"], "client_ip": r["ip"],
          "created_at": r["t"].strftime("%Y-%m-%d %H:%M:%S"),
          "actor_fp": _fp(r["token"]) if r["token"] else None} for r in records],
        scraping_all_windows=True))
    return {
        "dataset": {"seed": seed, "synthetic": True, "records": len(records),
                    "instances": len(instances), "instances_per_scenario": sc.INSTANCES,
                    "scenarios": [{"name": s.name, "description": s.description, "holdout": s.holdout,
                                   "expected": sorted(s.expected), "tolerated": sorted(s.tolerated)}
                                  for s in sc.SCENARIOS]},
        "ownership_context_supported": "ownership" in params,
        "scan": {"first": scan_counts, "rescan_created": rescan["created"],
                 "rescan_unchanged": rescan["unchanged"]},
        "alerts_total": len(alerts),
        "detection": evaluate(alerts, instances),
        "detection_tuning_set": evaluate(alerts, instances, holdout=False),
        "detection_holdout_set": evaluate(alerts, instances, holdout=True),
        "shadow_api": evaluate_shadow(shadow),
        "timings_not_deterministic": {
            "note": "wall-clock on this machine; varies run to run",
            "python": platform.python_version(), **timings},
    }


def _pct(v):
    return "n/a" if v is None else f"{v:.2f}"


def markdown(result):
    d = result["detection"]
    o = d["overall"]
    lines = [
        "# API Sentinel benchmark",
        "",
        f"Synthetic dataset: {result['dataset']['records']} records, "
        f"{result['dataset']['instances']} labelled instances "
        f"({result['dataset']['instances_per_scenario']} per scenario), seed {result['dataset']['seed']}. "
        f"Ownership context supported by this build: {result['ownership_context_supported']}.",
        "",
        "## Overall (instance x detection type)",
        "",
        f"TP {o['tp']}  FP {o['fp']}  TN {o['tn']}  FN {o['fn']}  |  precision {_pct(o['precision'])}  "
        f"recall {_pct(o['recall'])}  F1 {_pct(o['f1'])}  FPR {_pct(o['false_positive_rate'])}",
        "",
        "## Per detection type",
        "",
        "| type | TP | FP | TN | FN | precision | recall | F1 | FPR |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for t, m in d["per_detection_type"].items():
        lines.append(f"| {t} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | {_pct(m['precision'])} | "
                     f"{_pct(m['recall'])} | {_pct(m['f1'])} | {_pct(m['false_positive_rate'])} |")
    for key, title in (("detection_tuning_set", "Tuning set (in-sample)"),
                       ("detection_holdout_set", "Holdout set (not tuned on)")):
        m = result[key]["overall"]
        lines += ["", f"## {title}", "",
                  f"TP {m['tp']}  FP {m['fp']}  TN {m['tn']}  FN {m['fn']}  |  precision {_pct(m['precision'])}  "
                  f"recall {_pct(m['recall'])}  F1 {_pct(m['f1'])}  FPR {_pct(m['false_positive_rate'])}"]
    lines += ["", "## Per scenario (H = holdout)", "",
              "| scenario | expected | detection rate | false-alert rate |", "|---|---|---|---|"]
    for name, r in d["per_scenario"].items():
        lines.append(f"| {'H ' if name.startswith('h_') else ''}{name} | {', '.join(r['expected']) or '(none)'} | {_pct(r['detection_rate'])} | "
                     f"{_pct(r['false_alert_rate'])} |")
    s = result["shadow_api"]
    lines += ["", "## Shadow APIs", "",
              f"precision {_pct(s['precision'])}  recall {_pct(s['recall'])}  "
              f"predicted {s['predicted_shadow']}  false positives {s['false_positives']}  "
              f"missed {s['missed']}",
              "", f"Unattributed alerts (counted as FP): {len(d['unattributed_alerts'])}",
              "", "## Timings (non-deterministic)", "", "```", json.dumps(
                  result["timings_not_deterministic"], indent=1), "```", ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=20260105)
    ap.add_argument("--json", help="write JSON result here ('-' = stdout)")
    ap.add_argument("--markdown", help="write markdown report here ('-' = stdout)")
    args = ap.parse_args(argv)
    result = run(args.seed)
    for target, text in ((args.json, json.dumps(result, indent=2, sort_keys=True)),
                         (args.markdown, markdown(result))):
        if target == "-":
            print(text)
        elif target:
            Path(target).parent.mkdir(parents=True, exist_ok=True)
            Path(target).write_text(text + "\n")
    if not (args.json or args.markdown):
        print(markdown(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
