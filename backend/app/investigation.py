"""Alert investigation: one alert's rule, evidence, requests, enforcement and incident.

Everything comes from what Sentinel stored. Evidence is redacted again before it is
returned (defence in depth: capture already never stores bodies, headers or raw
credentials), and "blocked" is only reported when the access-control log recorded it.
"""

import re
import sqlite3

from app.analysis import ALL_CALLERS, BOLA_OUTCOMES, CATEGORIES, RULES, _bola_outcome
from app.capture import GATEWAY_PREFIX, REDACTED, sanitize_path
from app.discovery import id_segments, normalize_path, normalize_spec_template, path_only
from app.endpoint_risk import band
from app.storage import INCIDENT_GAP_SECONDS, get_alert, list_alerts, list_gateway_events, list_incidents
from app.timeutil import parse_timestamp

PROVENANCE = ("Derived by the Sentinel backend from captured request summaries (method, path with "
              "sensitive query values redacted, status, timing, client IP, keyed credential fingerprint). "
              "Request/response bodies, headers and raw credentials are never stored.")
_SENSITIVE_KEY = re.compile(r"authorization|cookie|password|passwd|secret|api[_-]?key|access_token|"
                            r"refresh_token|^token$|session", re.I)
_SAFE_KEYS = frozenset({"token_fingerprint"})  # keyed HMAC prefix, not a credential
_BEARER = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
REQUEST_SAMPLE = 50
BOLA_TYPES = frozenset(t for t, _, _ in BOLA_OUTCOMES.values())


def _identities(alert: dict) -> set[str]:
    """Who the alert is about: its actor plus the client IPs its evidence names."""
    return ({alert["actor"]} | _ips(alert)) - {ALL_CALLERS, "unknown"}


def _overlaps(a: dict, b: dict) -> bool:
    a0, a1 = parse_timestamp(a["first_seen"]), parse_timestamp(a["last_seen"])
    b0, b1 = parse_timestamp(b["first_seen"]), parse_timestamp(b["last_seen"])
    if None in (a0, a1, b0, b1):
        return False
    return (max(a0, b0) - min(a1, b1)).total_seconds() <= INCIDENT_GAP_SECONDS


def related_by_caller(alert: dict, alerts: list[dict]) -> list[dict]:
    """Other alerts sharing a caller identity (credential fingerprint or client IP) within the
    incident gap, across every category. Read-only: nothing is regrouped or changed.
    ``possible_duplicate``: same detection type and endpoint, i.e. likely the same activity
    recorded under two caller identities (e.g. a legacy IP-keyed alert and a credential-keyed one)."""
    mine = _identities(alert)
    out = []
    for other in alerts:
        if other["id"] == alert["id"] or not mine & _identities(other) or not _overlaps(alert, other):
            continue
        out.append({"id": other["id"], "detection_type": other["detection_type"], "endpoint": other["endpoint"],
                    "status": other["status"], "risk_score": other["risk_score"], "incident_id": other.get("incident_id"),
                    "shared": sorted(mine & _identities(other)),
                    "possible_duplicate": other["detection_type"] == alert["detection_type"]
                    and other["endpoint"] == alert["endpoint"]})
    return out


def redact(value):
    """Mask credential-like keys and credential/e-mail patterns anywhere in the evidence."""
    if isinstance(value, dict):
        return {k: REDACTED if _SENSITIVE_KEY.search(str(k)) and k not in _SAFE_KEYS else redact(v)
                for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return _EMAIL.sub("[REDACTED-EMAIL]", _BEARER.sub(r"\1 " + REDACTED, value))
    return value


def _ips(alert: dict) -> set[str]:
    md = alert["metadata"]
    ips = {str(md["client_ip"])} if md.get("client_ip") else set()
    ips |= {str(i) for i in md.get("ips", [])}
    if md.get("actor_type") == "ip":
        ips.add(alert["actor"])
    return ips - {"unknown"}


def _requests(db_path: str, alert: dict) -> tuple[list[dict], int]:
    """Captured requests behind the alert: its caller, its endpoints, its time span."""
    md = alert["metadata"]
    start = parse_timestamp(md.get("first_seen") or alert["first_seen"])
    end = parse_timestamp(alert["last_seen"])
    endpoints = set(md.get("endpoints") or [])
    objects_complete = bool(md.get("object_ids")) and len(md["object_ids"]) == md.get("unauthorized_objects")
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT method, path, status_code, client_ip, actor_fp, auth_type, payload_bytes,"
                            " created_at FROM captured_requests ORDER BY id").fetchall()
    out = []
    for r in rows:
        ts = parse_timestamp(r["created_at"])
        if ts is None or (start and ts < start) or (end and ts > end):
            continue
        template = normalize_path(path_only(r["path"]) or "/")
        if endpoints:
            if f"{r['method'].upper()} {template}" not in endpoints:
                continue
        elif template != alert["endpoint"]:
            continue
        if alert["actor"] != ALL_CALLERS and alert["actor"] not in (r["actor_fp"], r["client_ip"]) \
                and r["client_ip"] not in ({str(i) for i in md.get("ips", [])} if md.get("token_fingerprint") else set()):
            continue
        # A BOLA outcome alert is supported only by responses of that outcome (e.g. a confirmed
        # read is 2xx with content); the caller's other requests (404 probing) are not its evidence.
        if alert["detection_type"] in BOLA_TYPES:
            if _bola_outcome(int(r["status_code"] or 0)) != md.get("outcome", "confirmed"):
                continue
            # object_ids is capped at 20 in stored metadata: filter on it only when it is complete
            if objects_complete and "/".join(id_segments(path_only(r["path"]) or "/")) not in md["object_ids"]:
                continue
        out.append({"at": ts.isoformat(), "method": r["method"], "path": sanitize_path(r["path"]),
                    "status_code": r["status_code"], "client_ip": r["client_ip"],
                    "credential": f"{r['actor_fp'][:8]}…" if r["actor_fp"] else None,
                    "auth_type": r["auth_type"], "payload_bytes": r["payload_bytes"]})
    return out[-REQUEST_SAMPLE:], len(out)


_EVENT_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


def event_route(endpoint: str) -> str | None:
    """An access-control event's route in the alerts' form ("GET /api/x/{id}"), or None when
    the event names no concrete route (e.g. "ANY /gateway/* (no matching route)")."""
    method, _, path = str(endpoint or "").partition(" ")
    if method not in _EVENT_METHODS or not path.startswith("/") or "*" in path or " " in path:
        return None
    if path.startswith(GATEWAY_PREFIX + "/"):  # gateway events carry the /gateway prefix; captures do not
        path = path[len(GATEWAY_PREFIX):]
    return f"{method} {normalize_spec_template(path)}"


def _alert_routes(alert: dict) -> tuple[set[str], set[str]]:
    """(method+path routes, method-agnostic paths) the alert's evidence covers."""
    md = alert["metadata"]
    routes = set(md.get("endpoints") or [])
    method = str(md.get("method") or "").upper()
    if not routes and method:
        routes = {f"{method} {alert['endpoint']}"}
    return routes, set() if routes else {alert["endpoint"]}  # legacy alerts without a method: path only


def _enforcement(db_path: str, alert: dict) -> dict:
    ips = _ips(alert)
    start = parse_timestamp(alert["metadata"].get("first_seen") or alert["first_seen"])
    end = parse_timestamp(alert["last_seen"])
    routes, paths = _alert_routes(alert)
    candidates = [e for e in list_gateway_events(db_path, limit=5000)
                  if e["decision"] in ("blocked", "rate_limited") and e["client_ip"] in ips
                  and (start is None or parse_timestamp(e["last_seen"]) >= start)
                  and (end is None or parse_timestamp(e["first_seen"]) <= end)]
    # Same caller and time is not enough: a decision counts only for one of the alert's own routes.
    events = [e for e in candidates if (r := event_route(e["endpoint"])) is not None
              and (r in routes or r.split(" ", 1)[1] in paths)]
    unrelated = sum(e["count"] for e in candidates) - sum(e["count"] for e in events)
    counts = {d: sum(e["count"] for e in events if e["decision"] == d) for d in ("blocked", "rate_limited")}
    if counts["blocked"]:
        state = "blocked"
    elif counts["rate_limited"]:
        state = "rate_limited"
    else:
        state = "flagged_only"
    text = {
        "blocked": f"The access-control log recorded {counts['blocked']} blocked request(s) from this caller in this period.",
        "rate_limited": f"The access-control log recorded {counts['rate_limited']} rate-limited (429) request(s) "
                        "from this caller in this period; other requests were not blocked.",
        "flagged_only": "Observed and flagged only: no blocking or rate-limiting decision was recorded for this "
                        "caller in this period, so the requests reached the API (responses listed below).",
    }[state]
    if not ips:
        text += " The caller has no recorded client IP, so the access-control log could not be matched."
    if unrelated:
        text += (f" {unrelated} other access-control decision(s) for this caller in this period were for other "
                 "routes (or no matching route) and are not counted for this alert.")
    return {"state": state, "summary": text, "blocked": counts["blocked"], "rate_limited": counts["rate_limited"],
            "unrelated_events": unrelated,
            "events": [{k: e[k] for k in ("endpoint", "decision", "reason", "status_code", "count", "first_seen",
                                          "last_seen")} for e in events[:20]]}


def alert_detail(db_path: str, alert_id: int) -> dict | None:
    alert = get_alert(db_path, alert_id)
    if alert is None:
        return None
    md = alert["metadata"]
    rule_id = md.get("rule_id")
    rule = RULES.get(rule_id)
    requests, matched = _requests(db_path, alert)
    incident = next((i for i in list_incidents(db_path) if i["id"] == alert.get("incident_id")), None)
    missing = []
    if not rule:
        missing.append("rule_id: alert stored by an earlier detector version (before rule ids); current scans "
                       "update it only if they reproduce the same type, caller and endpoint")
    if not md.get("first_seen"):
        missing.append("evidence first_seen (older alert): the alert's first_seen is used instead")
    if not matched:
        missing.append("no captured request matches this alert's caller, endpoint and time span")
    missing.append("response bodies/sizes: never captured")
    missing.append("confidence: not modelled separately; the rule and outcome state what the evidence proves")
    method = str(md.get("method") or "").upper()
    return {
        "alert": {**alert, "metadata": redact(md)},
        "category": CATEGORIES.get(alert["detection_type"], alert["detection_type"]),
        "severity": band(alert["risk_score"]),
        "rule": {"id": rule_id, "category": rule[0], "title": rule[1], "explanation": rule[2]} if rule else None,
        "outcome": md.get("outcome"),
        "disposition": {"status": alert["status"], "note": alert["note"]},
        "enforcement": _enforcement(db_path, alert),
        "requests": requests,
        "requests_matched": matched,
        "incident": incident,
        "related_alerts": [a for a in (incident or {}).get("alerts", []) if a["id"] != alert["id"]],
        "related_by_caller": related_by_caller(alert, list_alerts(db_path)),
        "legacy": rule is None,
        "risk_link": {"method": method or None, "path": alert["endpoint"]},
        "provenance": PROVENANCE,
        "missing_fields": missing,
    }
