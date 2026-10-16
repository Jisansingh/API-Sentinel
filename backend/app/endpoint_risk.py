"""Explainable per-endpoint risk score (0-100), computed from stored evidence only.

Five factors, each capped, summing to at most 100 (see docs/RISK_AND_INVESTIGATION.md):

  exposure          20  undocumented (shadow) route 15; API gateway disabled 5
  authentication    20  a 2xx served with no credential 20; else HTTP Basic seen 5
  data_sensitivity  20  name-based sensitivity high 15 / medium 8; write method 5; admin/internal/export/debug 5
  behavior          15  active anomaly alerts: 10 for the first type, +5 per further type
  security_events   25  confirmed BOLA 25; else active abuse alerts 10 for the first type, +5 per further type (max 20)

Each alert counts in exactly one factor (anomaly vs abuse category), only while it is
open or acknowledged, and by distinct detection type, so re-scans, occurrences and
refreshes never inflate a score. Missing inputs are listed as unavailable and add 0
points: a gap in the data is never treated as evidence.
"""

from app.analysis import ANOMALY_MIN_HISTORY, CATEGORIES
from app.discovery import is_unresolved_route, normalize_path, path_only
from app.risk_scoring import RiskScorer

FACTOR_MAX = {"exposure": 20, "authentication": 20, "data_sensitivity": 20, "behavior": 15, "security_events": 25}
ACTIVE_STATUSES = frozenset({"open", "acknowledged"})
SENSITIVITY_POINTS = {"high": 15, "medium": 8, "low": 0}


def band(score: int) -> str:
    """Same bands as RiskScorer guidance: 0 none, 1-39 low, 40-69 medium, 70-100 high."""
    return "none" if score <= 0 else "low" if score < 40 else "medium" if score < 70 else "high"


def _stepped(types: set, first: int, step: int, cap: int) -> int:
    return min(cap, first + step * (len(types) - 1)) if types else 0


def _factor(name, points, evidence, alert_ids=(), unavailable=None):
    return {"factor": name, "points": min(points, FACTOR_MAX[name]), "max_points": FACTOR_MAX[name],
            "evidence": evidence, "alert_ids": sorted(alert_ids), "unavailable": unavailable}


def _alert_matches(alert: dict, method: str, path: str) -> bool:
    alert_method = str((alert.get("metadata") or {}).get("method") or "").upper()
    return alert["endpoint"] == path and alert_method in ("", method)


def score_endpoint(item: dict, *, spec_status: str, gateway_enabled: bool,
                   rows: list[dict], alerts: list[dict]) -> dict:
    """Score one inventory item. ``spec_status``: documented / shadow / unknown.
    ``rows``: its captured requests; ``alerts``: every stored alert (matched here)."""
    method, path = item["method"], item["path"]
    factors = []

    evidence, points, unavailable = [], 0, ["public reachability is not measured (Sentinel only sees captured traffic)"]
    if spec_status == "shadow":
        points += 15
        evidence.append("+15 observed in traffic but missing from the OpenAPI specification (shadow API)")
    elif spec_status == "documented":
        evidence.append("+0 documented in the OpenAPI specification")
    else:
        unavailable.append("no OpenAPI specification loaded: documentation status unknown")
    if gateway_enabled:
        evidence.append("+0 Sentinel API gateway enabled")
    else:
        points += 5
        evidence.append("+5 Sentinel API gateway disabled: no gateway policy in front of this API")
    factors.append(_factor("exposure", points, evidence, unavailable="; ".join(unavailable)))

    anon_ok = sum(1 for r in rows if r.get("auth_type") == "none" and 200 <= int(r.get("status_code") or 0) < 300)
    anon_denied = sum(1 for r in rows if r.get("auth_type") == "none" and int(r.get("status_code") or 0) in (401, 403))
    known = sorted({str(r.get("auth_type")) for r in rows if r.get("auth_type") not in (None, "unknown")})
    if anon_ok:
        factors.append(_factor("authentication", 20,
                               [f"+20 {anon_ok} successful response(s) to requests carrying no credential"]))
    elif not known:
        factors.append(_factor("authentication", 0, [], unavailable=(
            "authentication mechanism not recorded for these requests (captured before auth_type existed)")))
    else:
        basic = "basic" in known
        evidence = ["+5 HTTP Basic credentials observed (credential sent with every request)"] if basic else []
        evidence.append(f"+0 every successful request carried a credential ({', '.join(known)})")
        if anon_denied:
            evidence.append(f"+0 {anon_denied} unauthenticated request(s) were refused (401/403)")
        factors.append(_factor("authentication", 5 if basic else 0, evidence))

    level = item.get("data_sensitivity", "low")
    points = SENSITIVITY_POINTS.get(level, 0)
    evidence = [f"+{points} {level} sensitivity from route/parameter names (payloads are never read)"]
    if method in RiskScorer.WRITE_METHODS:
        points += 5
        evidence.append(f"+5 {method} changes data")
    if {s.lower() for s in path.split("/") if s} & RiskScorer.SENSITIVE_SEGMENTS:
        points += 5
        evidence.append("+5 administrative/internal/export/debug route")
    factors.append(_factor("data_sensitivity", points, evidence))

    matched = [a for a in alerts if _alert_matches(a, method, path)]
    active = [a for a in matched if a["status"] in ACTIVE_STATUSES]
    inactive = len(matched) - len(active)
    anomalies = [a for a in active if CATEGORIES.get(a["detection_type"]) == "anomaly"]
    abuse = [a for a in active if CATEGORIES.get(a["detection_type"]) != "anomaly"]

    types = {a["detection_type"] for a in anomalies}
    points = _stepped(types, 10, 5, 15)
    evidence = [f"active anomaly alerts: {', '.join(sorted(types))}"] if types else ["+0 no active anomaly alert"]
    factors.append(_factor("behavior", points, evidence, [a["id"] for a in anomalies],
                           unavailable=(f"fewer than {ANOMALY_MIN_HISTORY} captured requests: anomaly baselines "
                                        "cannot be established yet") if len(rows) < ANOMALY_MIN_HISTORY else None))

    types = {a["detection_type"] for a in abuse}
    if "bola" in types:
        points, evidence = 25, ["+25 confirmed cross-user object access (BOLA)"]
    else:
        points = _stepped(types, 10, 5, 20)
        evidence = [f"+{points} active suspected abuse alerts: {', '.join(sorted(types))}"] if types \
            else ["+0 no active security alert"]
    if inactive:
        evidence.append(f"{inactive} resolved/ignored alert(s) not counted")
    factors.append(_factor("security_events", points, evidence, [a["id"] for a in abuse]))

    score = min(100, sum(f["points"] for f in factors))
    unknown = [f["unavailable"] for f in factors if f["unavailable"]]
    # Provisional: little traffic, or an input other than (never measured) public reachability is missing.
    gaps = [f["factor"] for f in factors if f["unavailable"] and f["factor"] != "exposure"]
    if spec_status == "unknown":
        gaps.insert(0, "exposure")
    if len(rows) < ANOMALY_MIN_HISTORY or gaps:
        confidence = "provisional"
        why = ([f"only {len(rows)} captured request(s)"] if len(rows) < ANOMALY_MIN_HISTORY else []) + \
              [f"{g} input unavailable" for g in gaps]
    else:
        confidence, why = "established", [f"{len(rows)} captured requests and every factor input available"]
    parts = [f"{f['factor']} +{f['points']}" for f in factors if f["points"]]
    explanation = f"{score}/100 ({band(score)}): " + (", ".join(parts) if parts else "no risk factor observed")
    return {"method": method, "path": path, "score": score, "band": band(score), "factors": factors,
            "unavailable_inputs": unknown, "explanation": explanation,
            "confidence": confidence, "confidence_reason": "; ".join(why)}


def score_inventory(inventory, records, alerts, *, documented, shadow, spec_loaded, gateway_enabled):
    """Score every inventory endpoint (sorted by score, then method/path)."""
    by_endpoint: dict[tuple, list] = {}
    for r in records:
        key = (str(r.get("method", "")).upper(), normalize_path(path_only(str(r.get("path", "/"))) or "/"))
        by_endpoint.setdefault(key, []).append(r)
    out = []
    for item in inventory:
        if is_unresolved_route(item):
            continue  # only ever 404/405: no such endpoint was served, so there is nothing to score
        key = (item["method"], item["path"])
        status = "unknown" if not spec_loaded else "shadow" if key in shadow else "documented" if key in documented else "unknown"
        out.append(score_endpoint(item, spec_status=status, gateway_enabled=gateway_enabled,
                                  rows=by_endpoint.get(key, []), alerts=alerts))
    return sorted(out, key=lambda e: (-e["score"], e["method"], e["path"]))


def unscored_inventory(inventory) -> list[dict]:
    """Discovered routes that get no score, each with the reason (shown, never silently dropped)."""
    return [{"method": i["method"], "path": i["path"], "request_count": i["request_count"],
             "status_codes": i["status_codes"],
             "reason": "only ever answered 404/405: no endpoint was served, so it is not a confirmed live API"}
            for i in inventory if is_unresolved_route(i)]


def snapshot_view(result: dict) -> dict:
    """What a stored snapshot keeps: score plus per-factor points and alert ids."""
    return {"score": result["score"],
            "factors": {f["factor"]: {"points": f["points"], "alert_ids": f["alert_ids"]} for f in result["factors"]}}


def explain_change(before: dict, after: dict, before_at: str, after_at: str | None) -> dict:
    """Attribute a score change to factors and to alerts that appeared or stopped counting."""
    delta = after["score"] - before["score"]
    factors, added, removed = [], set(), set()
    for name in FACTOR_MAX:
        b = before["factors"].get(name, {"points": 0, "alert_ids": []})
        a = after["factors"].get(name, {"points": 0, "alert_ids": []})
        if a["points"] != b["points"]:
            factors.append({"factor": name, "from": b["points"], "to": a["points"], "delta": a["points"] - b["points"]})
        added |= set(a["alert_ids"]) - set(b["alert_ids"])
        removed |= set(b["alert_ids"]) - set(a["alert_ids"])
    return {"previous_score": before["score"], "current_score": after["score"], "delta": delta,
            "direction": "up" if delta > 0 else "down" if delta < 0 else "unchanged",
            "factors": factors, "new_alert_ids": sorted(added), "no_longer_counted_alert_ids": sorted(removed),
            "previous_at": before_at, "current_at": after_at}
