"use strict";
/* API Sentinel demo dashboard. Plain DOM, no framework, no network access except
   same-origin /api/* and /shop/* through the local proxy. Everything that comes
   from the backend or from captured traffic is inserted with textContent / text
   nodes only: this file never builds HTML from strings.

   Layout: a sidebar of objective-based tabs (Overview, API Discovery, Shadow
   APIs, Runtime Monitoring, Threat Detection, Risk & Analytics, Proxy &
   Protection, Access & Configuration, Evaluation) over the same panels and
   API calls the single-page version used. Switching tabs never re-fetches —
   every tab renders from the same already-fetched state, so tab switching is
   instant and the existing loaders/refresh cycle is unchanged. */

const AUTO_REFRESH_MS = 15000;
// The backend and the proxy load their code at start-up; this page is read from disk on
// every request. These must match app/config.py API_REVISION and serve.py PROXY_REVISION,
// so a process started from older code is reported instead of failing piecemeal.
const REQUIRED_API_REVISION = 6;
const REQUIRED_PROXY_REVISION = 6;
const ALERT_STATUSES = ["open", "acknowledged", "resolved", "ignored"];
const TYPE_LABELS = {
  scraping: ["Scraping", "info"],
  bola_enumeration: ["BOLA enumeration (attempt)", "warn"],
  bola: ["BOLA (confirmed)", "bad"],
  token_replay: ["Token replay", "bad"],
  bola_blocked: ["BOLA attempt (blocked)", "warn"],
  bola_inconclusive: ["BOLA attempt (inconclusive)", "warn"],
  access_denied: ["Repeated access denials", "warn"],
  rate_anomaly: ["Rate anomaly", "info"],
  error_spike: ["Server-error spike", "info"],
  payload_anomaly: ["Payload-size anomaly", "info"],
};
const TABS = ["overview", "discovery", "shadow", "monitoring", "detection", "risk", "proxy", "access", "evaluation"];

const state = {
  alerts: null, findings: null, inventory: null, shadow: null, access: null, baselines: null, source: null, risk: null,
  alertType: "", alertSev: "", alertTime: "", alertQ: "", detailId: null, history: null,
  alertFilter: "all", invFilter: "", invMethod: "", busy: false, timer: null, tab: "overview", mismatch: "",
};

const $ = (id) => document.getElementById(id);
/* Unsaved triage edits survive re-renders (refresh, auto-refresh, filter changes). */
const drafts = new Map();

/* ---------- tiny DOM helpers ---------- */
function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "data") Object.assign(node.dataset, value);
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (key in node) node[key] = value;
    else node.setAttribute(key, value);
  }
  node.append(...kids.flat().filter((k) => k != null && k !== false));
  return node;
}
const badge = (text, kind = "") => el("span", { class: `badge ${kind}`.trim(), text: String(text) });

/* ---------- formatting ---------- */
function parseUtc(value) {
  if (typeof value !== "string" || !value) return null;
  const hasZone = /(Z|[+-]\d\d:?\d\d)$/.test(value);
  const d = new Date(value.replace(" ", "T") + (hasZone ? "" : "Z"));
  return Number.isNaN(d.getTime()) ? null : d;
}
function relative(d) {
  const s = Math.round((Date.now() - d.getTime()) / 1000);
  if (s < 0) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
function timeCell(value) {
  const d = parseUtc(value);
  if (!d) return String(value ?? "");
  const iso = d.toISOString();
  return el("div", { title: `${iso} (UTC)` },
    el("div", { text: `${iso.slice(0, 10)} ${iso.slice(11, 19)}` }),
    el("div", { class: "small muted", text: relative(d) }));
}
// Same bands as the backend's RiskScorer guidance (< 40 low, < 70 medium).
function severity(score) {
  return score >= 70 ? "high" : score >= 40 ? "medium" : "low";
}
function riskCell(score) {
  const sev = severity(score);
  const bar = el("div", { class: "bar", "aria-hidden": "true" }, el("i"));
  bar.firstChild.style.width = `${Math.max(0, Math.min(100, Number(score) || 0))}%`;
  return el("div", { class: `risk ${sev}` },
    el("div", { class: "num", text: String(score) }),
    el("div", { class: "sevlabel", text: sev }), bar);
}
function typeBadge(type) {
  const [label, kind] = TYPE_LABELS[type] || [String(type), ""];
  return badge(label, kind);
}
function short(text, n = 14) {
  const s = String(text ?? "");
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
// Easy-to-copy identifiers (actor fingerprints, endpoints, evidence) without a mouse-only affordance.
function copyable(text, displayNode) {
  const btn = el("button", { class: "copy-btn", type: "button", "aria-label": `Copy ${text}`, text: "copy" });
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "copied"; btn.classList.add("copied");
      setTimeout(() => { btn.textContent = "copy"; btn.classList.remove("copied"); }, 1400);
    } catch (err) {
      toast("Could not copy: clipboard access was denied by the browser.", "bad");
    }
  });
  return el("span", { class: "copyable" }, displayNode, btn);
}

/* ---------- API access ---------- */
const AUTH_FAILED_TEXT = "Authentication failed — check proxy/backend API key configuration";
function explain(status, body) {
  const detail = body && body.detail != null ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : "";
  const clipped = short(detail, 220);
  if (status === 401) return AUTH_FAILED_TEXT + ": the backend refused the dashboard proxy's key.";
  if (status === 429) return "Rate limit reached for this endpoint; wait a moment and try again.";
  if (status === 503) return "Write endpoints are disabled: the backend was started without SENTINEL_API_KEY.";
  if (status === 502) return "The backend is unreachable from the dashboard proxy.";
  if (status === 403) return `The dashboard proxy refused the request${clipped ? `: ${clipped}` : "."}`;
  return `HTTP ${status}${clipped ? `: ${clipped}` : ""}`;
}
async function api(method, url, payload) {
  const init = { method, cache: "no-store" };
  if (payload !== undefined) {
    const zip = payload instanceof Blob;  // the source-scan ZIP upload is sent as raw bytes
    init.headers = { "Content-Type": zip ? "application/zip" : "application/json" };
    init.body = zip ? payload : JSON.stringify(payload);
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    throw new Error("Could not reach the dashboard proxy. Is demo/serve.py still running?");
  }
  const body = await res.json().catch(() => null);
  if (!res.ok) throw Object.assign(new Error(explain(res.status, body)), { status: res.status });
  return body;
}

/* ---------- feedback ---------- */
function toast(message, kind = "info") {
  const node = el("div", { class: `toast ${kind}` }, el("span", { text: message }),
    el("button", { type: "button", "aria-label": "Dismiss", text: "×", onclick: () => node.remove() }));
  $("toasts").append(node);
  setTimeout(() => node.remove(), kind === "bad" ? 10000 : 5000);
}
function setOpStatus(message, kind = "") {
  const node = $("opstatus");
  node.textContent = message;
  node.className = `opstatus ${kind}`.trim();
}
function stateBox(kind, message, retry) {
  return el("div", { class: `state ${kind}`, role: kind === "bad" ? "alert" : null },
    el("div", { text: message }),
    retry ? el("button", { class: "btn small", type: "button", text: "Retry", onclick: retry }) : null);
}
function setBody(id, ...children) {
  const body = $(id);
  if (!body) return;
  body.removeAttribute("aria-busy");
  body.replaceChildren(...children);
}
const COUNT_IDS = { alerts: "alerts-count", findings: "findings-count", shadow: "shadow-count", inventory: "inventory-count", access: "access-count", baselines: "baselines-count", risk: "risk-count", history: "history-count" };
const SECTIONS = Object.keys(COUNT_IDS);
function markUnavailable(name) {
  state[name] = null;
  $(COUNT_IDS[name]).textContent = "unavailable";
  if (name === "alerts") renderFilterChips();
}
function markBusy(id) {
  const body = $(id);
  if (!body) return;
  if (body.childElementCount) body.setAttribute("aria-busy", "true");
  else body.replaceChildren(el("div", { class: "state", text: "Loading…" }));
}

/* ---------- tables ---------- */
function makeTable(caption, columns, rows, rowClass) {
  const head = el("tr", {}, columns.map((c) => el("th", { scope: "col", class: (c.cls || "").includes("num") ? "num" : null, text: c.label })));
  const body = rows.map((row) => el("tr", { class: rowClass ? rowClass(row) : "" },
    columns.map((c) => {
      const content = c.cell(row);
      return el("td", { class: c.cls || "", "data-label": c.label },
        content instanceof Node ? content : String(content ?? ""));
    })));
  return el("div", { class: "table-wrap", tabIndex: 0, role: "region", "aria-label": caption },
    el("table", {}, el("caption", { text: caption }), el("thead", {}, head), el("tbody", {}, body)));
}

/* ---------- lightweight, dependency-free bar charts ----------
   No charting library exists in this project and the dashboard's Content-Security-Policy
   (script-src 'self', no external hosts) rules out loading one from a CDN, so a tiny
   proportional-bar component is built here instead of adding a dependency for a handful
   of charts. Every row shows its own number next to the bar (never color alone), so the
   chart is both a visualization and an accessible data table in one. */
function barChart(title, rows, opts = {}) {
  const wrap = el("div", { class: "chart" });
  wrap.append(el("div", { class: "chart-title", text: title }));
  if (opts.subtitle) wrap.append(el("div", { class: "chart-subtitle", text: opts.subtitle }));
  if (!rows.length) {
    wrap.append(el("div", { class: "chart-empty", text: opts.empty || "No data yet." }));
    return wrap;
  }
  const max = Math.max(1, ...rows.map((r) => r.value));
  const list = el("div", { class: "chart-rows", role: "img",
    "aria-label": `${title}: ${rows.map((r) => `${r.label} ${r.value}`).join(", ")}` });
  for (const r of rows) {
    const pct = Math.round((r.value / max) * 100);
    list.append(el("div", { class: "chart-row-item" },
      el("span", { class: `chart-row-label${opts.mono ? " mono" : ""}`, title: r.label, text: r.label }),
      el("div", { class: "chart-track" }, el("div", { class: `chart-fill ${r.kind || "info"}`, style: `width:${pct}%` })),
      el("span", { class: "chart-row-value", text: String(r.value) })));
  }
  wrap.append(list);
  return wrap;
}
function countBy(items, keyFn) {
  const counts = new Map();
  for (const item of items) {
    const k = keyFn(item);
    counts.set(k, (counts.get(k) || 0) + 1);
  }
  return counts;
}

/* ---------- evidence (only fields the backend actually returned) ---------- */
const FACTS = [
  ["pattern", (v) => (v === "low_and_slow" ? "low and slow" : String(v))],
  ["method", (v) => String(v)],
  ["request_count", (v) => `${v} requests`],
  ["distinct_resources", (v) => `${v} distinct paths`],
  ["distinct_ids", (v) => `${v} distinct IDs`],
  ["denied_ratio", (v) => `${Math.round(Number(v) * 100)}% denied`],
  ["unauthorized_objects", (v) => `${v} foreign objects read`],
  ["user_id", (v) => `user ${v}`],
  ["distinct_ips", (v) => `${v} IPs`],
  ["rapid_switch_ips", (v) => `${v} IPs switching within 60 s`],
  ["rule_id", (v) => `rule ${v}`],
  ["outcome", (v) => `outcome: ${v}`],
  ["denied_count", (v) => `${v} denials`],
  ["sequential_id_run", (v) => (v > 1 ? `${v} sequential IDs` : null)],
];
function evidence(item) {
  const md = item.metadata || {};
  const facts = FACTS.filter(([key]) => md[key] != null && md[key] !== "").map(([key, fmt]) => fmt(md[key])).filter(Boolean).map((text) => badge(text));
  const parts = md.breakdown
    ? Object.entries(md.breakdown).filter(([, v]) => v).map(([k, v]) => `${k.replace("_", " ")} +${v}`).join(", ")
    : "";
  // Skip the backend's "Low/Medium/High risk: …" band sentence: the band is already
  // shown from the score, and alerts stored before the risk_scoring.py fix carry one
  // computed on the pre-escalation score. The raw metadata below still shows it.
  const reasons = Array.isArray(md.reasons)
    ? md.reasons.filter((r) => !/^(No suspicious patterns|(Low|Medium|High) risk:)/.test(r)).join("\n") : "";
  const detailText = [parts && `Score breakdown: ${parts}`, reasons && `Reasons:\n${reasons}`,
    `Raw metadata:\n${JSON.stringify(md, null, 2)}`].filter(Boolean).join("\n\n");
  return el("div", {},
    el("div", { class: "reason", text: item.reason }),
    el("div", { class: "facts" }, facts),
    el("details", { class: "more" }, el("summary", { text: "Score breakdown and raw evidence" }),
      copyable(detailText, el("span", { class: "small muted", text: "copy raw evidence" })),
      el("pre", { class: "mono", text: detailText })));
}

/* ---------- Overview tab ---------- */
function renderCards() {
  const alerts = state.alerts, inv = state.inventory, sh = state.shadow, fin = state.findings, acc = state.access;
  const open = alerts ? alerts.filter((a) => a.status === "open") : null;
  const top = open && open.length ? Math.max(...open.map((a) => a.risk_score)) : null;
  const blocked = acc ? acc.events.items.filter((e) => e.decision === "blocked" || e.decision === "rate_limited")
    .reduce((n, e) => n + e.count, 0) : null;
  const cards = [
    ["Endpoints observed", inv ? inv.total_endpoints : "—", inv ? `${inv.total_requests} requests captured` : "unavailable"],
    ["Shadow APIs", sh ? (sh.spec_loaded ? sh.shadow_apis.length : "n/a") : "—",
      sh ? (sh.spec_loaded ? `${sh.documented.length} documented routes seen` : "no specification loaded") : "unavailable"],
    ["Live findings", fin ? fin.length : "—", "rolling windows, not stored"],
    ["Open alerts", open ? open.length : "—", alerts ? `${alerts.length} stored in total` : "unavailable"],
    ["Highest open risk", top == null ? "—" : top, top == null ? (alerts ? "no open alerts" : "unavailable") : severity(top)],
    ["Blocked / rate-limited", blocked == null ? "—" : blocked, acc ? `recorded, latest ${EVENT_ROW_LIMIT} event rows` : "access-control data unavailable"],
  ];
  $("cards").replaceChildren(...cards.map(([label, value, sub], i) =>
    el("div", { class: `card${i === 4 ? " alert-card" : ""}` },
      el("div", { class: "label", text: label }),
      el("div", { class: `value${i === 4 && top >= 70 ? " high" : ""}`, text: String(value) }),
      el("div", { class: "sub", text: sub }))));
}

function renderOverview() {
  const alerts = state.alerts, acc = state.access;
  const sevRows = alerts ? [["high", "High"], ["medium", "Medium"], ["low", "Low"]].map(([kind, label]) =>
    ({ label, value: alerts.filter((a) => severity(a.risk_score) === kind).length, kind })) : [];
  const decisionRows = acc ? ["allowed", "rate_limited", "blocked", "ignored"].map((d) => ({
    label: d.replace("_", " "),
    value: acc.events.items.filter((e) => e.decision === d).reduce((n, e) => n + e.count, 0),
    kind: d === "allowed" ? "ok" : d === "blocked" ? "bad" : d === "rate_limited" ? "warn" : "info",
  })) : [];
  const charts = el("div", { class: "chart-grid" },
    barChart("Alerts by risk band", alerts ? sevRows : [], { empty: "No stored alerts yet." }),
    barChart("Proxy & protection decisions", acc ? decisionRows : [],
      { empty: acc ? "No access-control events yet." : "Access control data not loaded." }));
  const recent = alerts && alerts.length
    ? el("div", { class: "recent-list" }, alerts.slice(0, 5).map((a) =>
        el("div", { class: "recent-item" }, riskCell(a.risk_score),
          el("div", {}, typeBadge(a.detection_type), el("div", { class: "path", text: a.endpoint })),
          el("div", { class: "when" }, timeCell(a.last_seen)))))
    : stateBox("info", "No recent security events yet. Generate sample traffic, then press Run scan.");
  setBody("overview-charts", charts);
  setBody("overview-protection", protectionBanner(acc));
  setBody("overview-recent", el("h3", { text: "Recent security events" }), recent);
}

/* ---------- Threat Detection tab ---------- */
function renderFilterChips() {
  const counts = { all: state.alerts ? state.alerts.length : 0 };
  for (const s of ALERT_STATUSES) counts[s] = state.alerts ? state.alerts.filter((a) => a.status === s).length : 0;
  $("alert-filter").replaceChildren(...["all", ...ALERT_STATUSES].map((s) =>
    el("button", {
      class: "chip", type: "button", text: `${s} (${counts[s]})`,
      "aria-pressed": String(state.alertFilter === s),
      onclick: () => { state.alertFilter = s; renderAlerts(); },
    })));
}

function triageControl(alert) {
  const select = el("select", { "aria-label": `Status of alert ${alert.id}` },
    ALERT_STATUSES.map((s) => el("option", { value: s, text: s, selected: s === alert.status })));
  const draft = drafts.get(alert.id) || {};
  select.value = draft.status ?? alert.status;
  const note = el("input", {
    type: "text", maxLength: 500, value: draft.note ?? (alert.note || ""), placeholder: "Analyst note (optional)",
    "aria-label": `Note for alert ${alert.id}`,
  });
  const remember = () => drafts.set(alert.id, { status: select.value, note: note.value });
  select.addEventListener("change", remember);
  note.addEventListener("input", remember);
  const msg = el("div", { class: "rowmsg", role: "status" });
  const save = el("button", { class: "btn small", type: "button", text: "Save", data: { alertSave: String(alert.id) } });
  save.addEventListener("click", async () => {
    const payload = { status: select.value };
    if (note.value !== (alert.note || "")) payload.note = note.value;
    if (payload.status === alert.status && !("note" in payload)) {
      msg.className = "rowmsg"; msg.textContent = "No changes to save.";
      return;
    }
    for (const c of [select, note, save]) c.disabled = true;
    save.setAttribute("aria-busy", "true");
    msg.className = "rowmsg"; msg.textContent = "Saving…";
    try {
      const updated = await api("PATCH", `/api/alerts/${Number(alert.id)}`, payload);
      Object.assign(alert, updated);
      drafts.delete(alert.id);
      toast(`Alert #${alert.id} is now ${alert.status}${"note" in payload ? " (note saved)" : ""}.`, "ok");
      renderAlerts();
      renderCards();
      renderOverview();
      renderRisk();
      loaders.risk();  // triage changes endpoint scores (and records a snapshot)
      if (state.detailId === alert.id && !$("alert-detail").hidden) openAlertDetail(alert.id, false);
      const again = document.querySelector(`[data-alert-save="${Number(alert.id)}"]`);
      if (again) again.focus();
    } catch (err) {
      msg.className = "rowmsg bad"; msg.textContent = `Not saved: ${err.message}`;
      toast(`Alert #${alert.id} was not updated. ${err.message}`, "bad");
      for (const c of [select, note, save]) c.disabled = false;
      save.removeAttribute("aria-busy");
    }
  });
  return el("div", { class: "triage" }, select, note, el("div", { class: "row" }, save), msg);
}

function renderAlerts() {
  renderFilterChips();
  if (state.alerts == null) return;
  const types = [...new Set(state.alerts.map((a) => a.detection_type))].sort();
  $("alert-type").replaceChildren(el("option", { value: "", text: "All types" }),
    ...types.map((t) => el("option", { value: t, text: (TYPE_LABELS[t] || [t])[0], selected: t === state.alertType })));
  const q = state.alertQ.trim().toLowerCase();
  const since = state.alertTime ? Date.now() - Number(state.alertTime) * 3600e3 : null;
  const shown = state.alerts.filter((a) => (state.alertFilter === "all" || a.status === state.alertFilter)
    && (!state.alertType || a.detection_type === state.alertType)
    && (!state.alertSev || severity(a.risk_score) === state.alertSev)
    && (!q || `${a.endpoint} ${a.actor}`.toLowerCase().includes(q))
    && (since == null || (parseUtc(a.last_seen) || 0) >= since));
  $("alerts-count").textContent = `${shown.length} shown of ${state.alerts.length}`;
  if (!state.alerts.length) {
    return setBody("alerts-body", stateBox("info", "No stored alerts yet. Generate sample traffic, then press Run scan."));
  }
  if (!shown.length) return setBody("alerts-body", stateBox("", "No alerts match the filters."));
  setBody("alerts-body", makeTable("Persistent alerts", [
    { label: "Risk", cls: "nowrap", cell: (a) => riskCell(a.risk_score) },
    { label: "Detection", cell: (a) => el("div", {}, typeBadge(a.detection_type),
      el("div", { class: "small muted", text: `alert #${a.id}${a.incident_id ? ` · incident INC-${a.incident_id}` : ""}` }),
      el("button", { class: "btn small", type: "button", text: "Investigate", "aria-label": `Investigate alert ${a.id}`,
        onclick: () => openAlertDetail(a.id) })) },
    { label: "Endpoint", cls: "path", cell: (a) => copyable(a.endpoint, el("span", { text: a.endpoint })) },
    { label: "Actor", cls: "nowrap mono", cell: (a) => copyable(a.actor, el("span", { title: a.actor, text: short(a.actor, 16) })) },
    { label: "Why it fired", cell: evidence },
    { label: "Activity", cls: "nowrap", cell: (a) => el("div", {},
      el("div", { text: `seen ${a.occurrences}×` }),
      el("div", { class: "small muted" }, "first ", timeCell(a.first_seen)),
      el("div", { class: "small muted" }, "last ", timeCell(a.last_seen))) },
    { label: "Triage", cell: triageControl },
  ], shown, (a) => `sev-${severity(a.risk_score)}`));
}

/* detection-type-rows:start (pure; tested in Node by tests/test_phase5_audit_fixes.py) */
// One bar per stored detection type (raw types, so "BOLA (confirmed)" and "BOLA enumeration" are separate).
function detectionTypeRows(alerts, labels) {
  const counts = new Map();
  for (const a of alerts) counts.set(a.detection_type, (counts.get(a.detection_type) || 0) + 1);
  return [...counts].map(([type, value]) => ({ type, label: (labels[type] || [type])[0], value, kind: (labels[type] || ["", ""])[1] || "info" }))
    .sort((a, b) => b.value - a.value || a.type.localeCompare(b.type));
}
/* detection-type-rows:end */
function renderDetectionCharts() {
  const alerts = state.alerts;
  if (!$("detection-charts")) return;
  const byType = alerts ? detectionTypeRows(alerts, TYPE_LABELS) : [];
  const bySeverity = alerts ? [["high", "High"], ["medium", "Medium"], ["low", "Low"]].map(([kind, label]) =>
    ({ label, value: alerts.filter((a) => severity(a.risk_score) === kind).length, kind })) : [];
  setBody("detection-charts", el("div", { class: "chart-grid" },
    barChart("Alerts by detection type", byType, { empty: "No stored alerts yet." }),
    barChart("Alerts by severity", bySeverity, { empty: "No stored alerts yet." })));
}

/* ---------- Live findings (Runtime Monitoring tab) ---------- */
function renderFindings() {
  if (state.findings == null) return;
  $("findings-count").textContent = `${state.findings.length} now`;
  if (!state.findings.length) {
    return setBody("findings-body", stateBox("", "No live findings in the current windows. This is expected when traffic is quiet or has aged out; stored alerts are listed above."));
  }
  setBody("findings-body", makeTable("Live findings", [
    { label: "Risk", cls: "nowrap", cell: (f) => riskCell(f.risk_score) },
    { label: "Detection", cell: (f) => typeBadge(f.detection_type) },
    { label: "Endpoint", cls: "path", cell: (f) => f.endpoint },
    { label: "Why it fired", cell: evidence },
    { label: "Latest evidence (UTC)", cls: "nowrap", cell: (f) => timeCell(f.timestamp) },
  ], state.findings, (f) => `sev-${severity(f.risk_score)}`));
}

function renderMonitoringChart() {
  if (!$("monitoring-chart")) return;
  const inv = state.inventory;
  const rows = inv ? [...inv.items].sort((a, b) => b.request_count - a.request_count).slice(0, 10)
    .map((r) => ({ label: `${r.method} ${r.path}`, value: r.request_count, kind: "info" })) : [];
  setBody("monitoring-chart", barChart("Requests by endpoint (top 10)", rows,
    { mono: true, empty: "Nothing captured yet. Send traffic, or press Generate sample traffic." }));
}

/* ---------- Runtime Monitoring tab: behavioral baselines ---------- */
const fmtShare = (v) => `${(v * 100).toFixed(1)}%`;
const BASELINE_STATES = { no_baseline: ["no baseline yet", ""], insufficient: ["insufficient samples", "warn"],
  ready: ["baseline ready", "ok"], deviation: ["deviation detected", "bad"] };
function baselineCell(r) {
  const [label, kind] = BASELINE_STATES[r.baseline_state] || ["state not reported", ""];
  return el("div", {}, badge(label, kind), el("div", { class: "small muted", text: `${r.baseline_samples} matching earlier hour(s)` }));
}
function rateCell(r) {
  if (r.rate_anomaly) return el("div", {}, badge("above baseline", "bad"), el("div", { class: "small muted reason", text: r.rate_anomaly_reason }));
  if (r.rate_alert_suppressed_reason) return el("div", {}, badge("not enough history", ""), el("div", { class: "small muted reason", text: r.rate_alert_suppressed_reason }));
  return badge("normal", "ok");
}
function renderBaselines() {
  const b = state.baselines;
  if (b == null) return;
  $("baselines-count").textContent = `${b.endpoints.length} endpoints · ${b.callers.length} caller/endpoint pairs · ${b.requests_analyzed} requests · ${b.window_days}-day window`;
  if (!b.endpoints.length) return setBody("baselines-body", stateBox("info", `No captured traffic in the last ${b.window_days} days, so there is no baseline yet.`));
  const rate = [
    { label: "Baseline", cell: baselineCell },
    { label: "Current hour", cls: "num", cell: (r) => r.current_hour_requests },
    { label: "Baseline median (samples)", cls: "num", cell: (r) => `${r.baseline_median_requests} (${r.baseline_samples})` },
    { label: "Rate", cell: rateCell },
  ];
  setBody("baselines-body",
    makeTable("Endpoint baselines", [
      { label: "Endpoint", cls: "path", cell: (r) => r.endpoint },
      { label: "Requests", cls: "num", cell: (r) => r.request_count },
      { label: "Req/hour", cls: "num", cell: (r) => r.requests_per_hour_observed },
      ...rate,
      { label: "Payload bytes (mean / max)", cls: "num nowrap", cell: (r) => `${r.payload_bytes_mean} / ${r.payload_bytes_max}` },
      { label: "5xx rate", cls: "num", cell: (r) => fmtShare(r.server_error_rate) },
      { label: "Last seen (UTC)", cls: "nowrap", cell: (r) => timeCell(r.last_seen) },
    ], b.endpoints, (r) => (r.rate_anomaly ? "sev-high" : "")),
    el("details", { class: "more" }, el("summary", { text: `${b.callers.length} caller/endpoint baselines` }),
      makeTable("Caller baselines", [
        { label: "Caller", cls: "mono", cell: (r) => copyable(r.caller, el("span", { text: short(r.caller, 28) })) },
        { label: "Endpoint", cls: "path", cell: (r) => r.endpoint },
        { label: "Requests", cls: "num", cell: (r) => r.request_count },
        ...rate,
        { label: "Mean payload bytes", cls: "num", cell: (r) => r.payload_bytes_mean },
        { label: "5xx rate", cls: "num", cell: (r) => fmtShare(r.server_error_rate) },
      ], [...b.callers].sort((x, y) => y.request_count - x.request_count))),
    el("p", { class: "small muted", text: `Method: ${b.baseline_method}. Generated ${b.generated_at}.` }));
}

/* ---------- Runtime Monitoring tab: real traffic history and adaptive baselines ---------- */
const HISTORY_STATES = { no_baseline: ["no baseline", ""], insufficient: ["insufficient evidence", "warn"],
  ready: ["baseline ready", "ok"], deviation: ["deviation", "bad"] };
function sparkline(trend) {
  const max = Math.max(1, ...trend.map((t) => t.requests));
  const wrap = el("div", { class: "spark", role: "img",
    "aria-label": `Last ${trend.length} active hours: ${trend.map((t) => t.requests).join(", ")} requests` });
  for (const t of trend) {
    const bar = el("i", { class: t.quarantined ? "q" : "", title: `${t.bucket} UTC: ${t.requests} requests${t.quarantined ? " (quarantined)" : ""}` });
    bar.style.height = `${Math.max(8, Math.round((t.requests / max) * 100))}%`;
    wrap.append(bar);
  }
  return wrap;
}
function renderHistory() {
  const h = state.history;
  if (h == null) return;
  const counts = countBy(h.endpoints, (e) => e.state);
  $("history-count").textContent = `${h.endpoints.length} endpoints · ${["deviation", "ready", "insufficient", "no_baseline"]
    .filter((s) => counts.get(s)).map((s) => `${counts.get(s)} ${HISTORY_STATES[s][0]}`).join(" · ") || "no history yet"} · ${h.window_days}-day window`;
  if (!h.endpoints.length) return setBody("history-body", stateBox("info", "No real traffic has been captured by this instance yet."));
  setBody("history-body", makeTable("Real traffic history and adaptive baselines", [
    { label: "Endpoint", cls: "path", cell: (e) => `${e.method} ${e.endpoint}` },
    { label: "Baseline", cell: (e) => el("div", {}, badge(...HISTORY_STATES[e.state] || [e.state, ""]),
      el("div", { class: "small muted", text: `confidence: ${e.confidence}` })) },
    { label: "Observations", cls: "num", cell: (e) => e.observations },
    { label: "Time span (UTC)", cls: "nowrap", cell: (e) => el("div", {}, el("div", { text: e.first_seen ? `${e.first_seen.slice(0, 13)}h → ${e.last_update.slice(0, 13)}h` : "no history in window" }),
      el("div", { class: "small muted", text: `${e.span_hours} h · ${e.active_hours} active h · ${e.quarantined_hours} quarantined` })) },
    { label: "This hour", cls: "nowrap", cell: (e) => `${e.current_hour.requests}${e.current_hour.threshold != null ? ` / ${e.current_hour.threshold}` : ""}` },
    { label: "Trend", cell: (e) => sparkline(e.trend) },
    { label: "Explanation", cell: (e) => el("span", { class: "reason", text: e.explanation }) },
  ], h.endpoints, (e) => (e.state === "deviation" ? "sev-high" : "")),
  el("p", { class: "small muted", text: `Source: ${h.source}. Generated ${h.generated_at} UTC. Evidence required: ${h.evidence_required.min_days} days, ${h.evidence_required.min_span_hours} h span, ${h.evidence_required.min_active_hours} active hours.` }));
}

/* ---------- Shadow APIs tab ---------- */
function renderShadow() {
  const sh = state.shadow;
  if (sh == null) return;
  if (!sh.spec_loaded) {
    $("shadow-count").textContent = "specification not loaded";
    return setBody("shadow-body",
      stateBox("warn", `No OpenAPI specification is loaded (${sh.spec_error || "unknown reason"}). The backend lists every observed route as "documentation status unknown"; none of them is confirmed as shadow. Start the backend with OPENAPI_SPEC_PATH or enter a file in the allowed folder above.`),
      sh.shadow_apis.length ? el("details", { class: "more" }, el("summary", { text: `${sh.shadow_apis.length} observed routes with unknown status` }),
        el("pre", { class: "mono", text: sh.shadow_apis.map((r) => `${r.method} ${r.path}`).join("\n") })) : null);
  }
  const deprecated = sh.deprecated_apis || [];
  $("shadow-count").textContent = `${sh.shadow_apis.length} undocumented · ${deprecated.length} deprecated · ${sh.documented.length} documented`;
  const parts = [];
  if (!sh.shadow_apis.length) {
    parts.push(stateBox("info", "No undocumented routes were observed. Every route seen in traffic is covered by the specification."));
  } else {
    parts.push(makeTable("Undocumented (shadow) APIs", [
      { label: "Status", cell: () => badge("shadow", "bad") },
      { label: "Method", cls: "method nowrap", cell: (r) => r.method },
      { label: "Path", cls: "path", cell: (r) => r.path },
      { label: "Requests", cell: (r) => r.request_count },
      { label: "Last seen (UTC)", cls: "nowrap", cell: (r) => timeCell(r.last_seen) },
      { label: "Reason", cell: (r) => el("span", { class: "reason", text: r.reason }) },
    ], sh.shadow_apis));
  }
  parts.push(el("details", { class: "more" }, el("summary", { text: `${sh.documented.length} documented routes seen in traffic` }),
    sh.documented.length ? makeTable("Documented routes", [
      { label: "Status", cell: () => badge("documented", "ok") },
      { label: "Method", cls: "method nowrap", cell: (r) => r.method },
      { label: "Path", cls: "path", cell: (r) => r.path },
    ], sh.documented) : el("p", { class: "muted", text: "None of the observed routes is in the specification." })));
  parts.splice(1, 0, deprecated.length ? makeTable("Deprecated APIs still receiving traffic", [
    { label: "Status", cell: () => badge("deprecated", "warn") },
    { label: "Method", cls: "method nowrap", cell: (r) => r.method },
    { label: "Path", cls: "path", cell: (r) => r.path },
    { label: "Requests", cell: (r) => r.request_count },
    { label: "Last seen (UTC)", cls: "nowrap", cell: (r) => timeCell(r.last_seen) },
    { label: "Reason", cell: (r) => el("span", { class: "reason", text: r.reason }) },
  ], deprecated) : el("p", { class: "small muted", text: "Deprecated: no observed route is marked deprecated in the specification." }),
  el("p", { class: "small muted", text: `Unmanaged: ${sh.unmanaged_note || "not reported by this backend"}. Undocumented is not the same as unmanaged.` }));
  setBody("shadow-body", ...parts);
}

/* ---------- API Discovery tab ---------- */
function specStatus(row) {
  const sh = state.shadow;
  if (!sh || !sh.spec_loaded) return badge("no spec", "");
  const key = `${row.method} ${row.path}`;
  if (sh.shadow_apis.some((r) => `${r.method} ${r.path}` === key)) return badge("shadow", "bad");
  if (sh.documented.some((r) => `${r.method} ${r.path}` === key)) return badge("documented", "ok");
  return badge("404/405 only", "");
}
// Same endpoint identity (method + normalized path) as the Risk & Analytics scores.
function inventoryRisk(row) {
  const r = state.risk;
  if (!r) return el("span", { class: "small muted", text: "risk not loaded" });
  const scored = r.items.find((e) => e.method === row.method && e.path === row.path);
  if (scored) return el("div", {}, riskCell(scored.score), el("div", { class: "small muted", text: scored.confidence || "" }));
  const excluded = (r.excluded || []).find((e) => e.method === row.method && e.path === row.path);
  return el("span", { class: "small muted", text: excluded ? "not scored (404/405 only)" : "not scored" });
}
function renderInventory() {
  if (state.inventory == null) return;
  const inv = state.inventory;
  const q = state.invFilter.trim().toLowerCase();
  const m = state.invMethod;
  const rows = inv.items.filter((r) => (!q || `${r.method} ${r.path}`.toLowerCase().includes(q)) && (!m || r.method === m));
  $("inventory-count").textContent = `${rows.length} of ${inv.total_endpoints} endpoints · ${inv.total_requests} requests`;
  if (!inv.items.length) return setBody("inventory-body", stateBox("info", "Nothing has been captured yet. Send traffic through the monitored API (or press Generate sample traffic)."));
  if (!rows.length) return setBody("inventory-body", stateBox("", "No endpoints match the filter.",
    () => { $("inv-search").value = ""; $("inv-method").value = ""; state.invFilter = ""; state.invMethod = ""; renderInventory(); }));
  setBody("inventory-body", makeTable("API inventory", [
    { label: "Method", cls: "method nowrap", cell: (r) => r.method },
    { label: "Path", cls: "path", cell: (r) => copyable(r.path, el("span", { text: r.path })) },
    { label: "Spec", cell: specStatus },
    { label: "Requests", cell: (r) => r.request_count },
    { label: "Status codes", cell: (r) => el("div", { class: "facts" }, r.status_codes.map((c) =>
      badge(c, c < 300 ? "ok" : c < 400 ? "info" : c < 500 ? "warn" : "bad"))) },
    { label: "Last seen (UTC)", cls: "nowrap", cell: (r) => timeCell(r.last_seen) },
    { label: "Query parameters", cls: "path", cell: (r) => r.query_params.join(", ") || "—" },
    { label: "Served", cell: (r) => (r.confirmed_live === false ? badge("404/405 only", "warn") : badge("served", "ok")) },
    { label: "Authentication", cell: (r) => (r.authentication_types || ["unknown"]).join(", ") },
    { label: "Sensitivity", cell: (r) => el("div", {}, el("div", { text: r.data_sensitivity }),
      el("div", { class: "small muted reason", text: r.sensitivity_basis || "basis not reported by this backend" })) },
    { label: "Risk", cls: "nowrap", cell: inventoryRisk },
  ], rows));
  const methods = [...new Set(inv.items.map((r) => r.method))].sort();
  $("inv-method").replaceChildren(el("option", { value: "", text: "All methods" }),
    ...methods.map((mm) => el("option", { value: mm, text: mm, selected: mm === m })));
}

/* ---------- API Discovery tab: source-code APIs (on demand; there is no project listing) ---------- */
// Path parameters are named in source ({order_id}) but normalized in traffic ({id}).
const routeKey = (method, path) => `${method} ${path.replace(/\{[^/}]*\}/g, "{}")}`;
function renderSource() {
  const src = state.source;
  if (src == null) return;
  const seen = new Set((state.inventory ? state.inventory.items : []).map((r) => routeKey(r.method, r.path)));
  const inTraffic = src.items.filter((r) => seen.has(routeKey(r.method, r.path))).length;
  $("source-count").textContent = `${src.project_id}: ${src.items.length} routes` + (state.inventory ? ` · ${inTraffic} seen in traffic` : "");
  if (!src.items.length) return setBody("source-body", stateBox("info", `No source routes are stored for project "${src.project_id}". Check the project ID, or scan the project first.`));
  setBody("source-body", makeTable(`Source-code APIs for ${src.project_id}`, [
    { label: "Method", cls: "method nowrap", cell: (r) => r.method },
    { label: "Path", cls: "path", cell: (r) => copyable(r.path, el("span", { text: r.path })) },
    { label: "In traffic", cell: (r) => (!state.inventory ? badge("inventory unavailable", "")
      : seen.has(routeKey(r.method, r.path)) ? badge("seen", "ok") : badge("not seen", "warn")) },
    { label: "Source", cls: "path", cell: (r) => `${r.source_file}:${r.line_number}` },
    { label: "Detector", cell: (r) => r.detector },
    { label: "Confidence", cell: (r) => r.confidence },
    { label: "Last scanned (UTC)", cls: "nowrap", cell: (r) => timeCell(r.last_seen) },
  ], src.items));
}
async function sourceAction(button, work) {
  button.disabled = true;
  button.setAttribute("aria-busy", "true");
  markBusy("source-body");
  try {
    await work();
  } catch (err) {
    setBody("source-body", stateBox("bad", `Source-code APIs could not be loaded. ${err.message}`));
    $("source-count").textContent = "unavailable";
    setOpStatus(`Source-code APIs: ${err.message}`, "bad");
  } finally {
    button.disabled = false;
    button.removeAttribute("aria-busy");
  }
}
function loadSource() {
  const project = $("src-project").value.trim();
  if (!project) return setBody("source-body", stateBox("warn", "Enter a project ID to load its saved scan results."));
  return sourceAction($("btn-src-load"), async () => {
    state.source = await api("GET", "/api/source-apis?project_id=" + encodeURIComponent(project));
    renderSource();
  });
}
function scanSource() {
  const kind = $("src-type").value, project = $("src-project").value.trim(), target = $("src-target").value.trim();
  const file = $("src-zip").files[0];
  if (kind === "upload" ? !file : !target) {
    return setBody("source-body", stateBox("warn", kind === "upload" ? "Choose a ZIP file to scan." : kind === "github" ? "Enter a public GitHub repository URL." : "Enter a folder path on the backend host."));
  }
  return sourceAction($("btn-src-scan"), async () => {
    setOpStatus("Scanning source code…");
    const r = kind === "upload"
      ? await api("POST", "/api/source-scan/upload" + (project ? `?project_id=${encodeURIComponent(project)}` : ""), file)
      : await api("POST", "/api/source-scan", { source_type: kind, project_id: project || undefined, [kind === "github" ? "repo_url" : "local_path"]: target });
    $("src-project").value = r.project_id;
    state.source = { project_id: r.project_id, items: r.items };
    renderSource();
    const msg = `Source scan of ${r.repository || r.project_id}: ${r.files_scanned} files scanned, ${r.routes_found} routes found` + (r.scan_errors ? `, ${r.scan_errors} unreadable files` : "") + ".";
    setOpStatus(msg, "ok"); toast(msg, "ok");
  });
}
function syncSourceInputs() {
  const kind = $("src-type").value;
  $("src-zip").hidden = kind !== "upload";
  $("src-target").hidden = kind === "upload";
  $("src-target").placeholder = kind === "github" ? "Public repository URL (HTTPS)" : "/absolute/folder/on/the/backend/host";
}

/* ---------- Risk & Analytics tab ---------- */
function renderRisk() {
  if (!$("risk-charts")) return;
  const alerts = state.alerts;
  if (alerts == null) {
    setBody("risk-charts", stateBox("", "Alert data not loaded yet."));
    return setBody("risk-ranking", "");
  }
  const bands = [["high", "High (≥ 70)"], ["medium", "Medium (40–69)"], ["low", "Low (< 40)"]].map(([kind, label]) =>
    ({ label, value: alerts.filter((a) => severity(a.risk_score) === kind).length, kind }));
  const byEndpoint = new Map();
  for (const a of alerts) {
    const prev = byEndpoint.get(a.endpoint);
    if (!prev || a.risk_score > prev.risk_score) byEndpoint.set(a.endpoint, a);
  }
  const ranked = [...byEndpoint.values()].sort((a, b) => b.risk_score - a.risk_score);
  const top = ranked.slice(0, 8).map((a) => ({ label: a.endpoint, value: a.risk_score, kind: severity(a.risk_score) }));
  setBody("risk-charts", el("div", { class: "chart-grid" },
    barChart("Risk distribution (stored alerts)", bands, { empty: "No stored alerts yet." }),
    barChart("Highest-risk endpoints", top, { mono: true, empty: "No stored alerts yet." })));
  setBody("risk-ranking", ranked.length ? makeTable("Endpoint risk ranking", [
    { label: "Rank", cell: () => "" },  // makeTable() has no row index; filled in below
    { label: "Endpoint", cls: "path", cell: (a) => a.endpoint },
    { label: "Max risk", cls: "nowrap", cell: (a) => riskCell(a.risk_score) },
    { label: "Top detection", cell: (a) => typeBadge(a.detection_type) },
    { label: "Alerts at this endpoint", cell: (a) => alerts.filter((x) => x.endpoint === a.endpoint).length },
  ], ranked, (a) => `sev-${severity(a.risk_score)}`) : stateBox("info", "No stored alerts yet."));
  if (ranked.length) {
    $("risk-ranking").querySelectorAll("tbody tr").forEach((tr, i) => { tr.querySelector("td").textContent = String(i + 1); });
  }
}

/* ---------- alert investigation (Threat Detection tab) ---------- */
const ENFORCEMENT = { blocked: ["blocked", "bad"], rate_limited: ["rate limited", "warn"], flagged_only: ["flagged only, not blocked", "info"] };
function kv(rows) {
  return el("dl", { class: "kv" }, rows.filter(([, v]) => v != null && v !== "").flatMap(([k, v]) =>
    [el("dt", { text: k }), el("dd", {}, v instanceof Node ? v : String(v))]));
}
async function openAlertDetail(id, focus = true) {
  state.detailId = id;
  $("alert-detail").hidden = false;
  $("detail-count").textContent = `alert #${id}`;
  markBusy("detail-body");
  if (focus) $("detail-h").focus();
  try {
    renderAlertDetail(await api("GET", "/api/alerts/" + encodeURIComponent(id)));
  } catch (err) {
    setBody("detail-body", stateBox("bad", `Could not load alert #${id}. ${err.message}`, () => openAlertDetail(id)));
  }
}
function renderAlertDetail(d) {
  const a = d.alert, md = a.metadata || {}, enf = d.enforcement;
  const [enfLabel, enfKind] = ENFORCEMENT[enf.state] || [enf.state, ""];
  setBody("detail-body",
    kv([
      ["Alert", `#${a.id}`], ["Incident", d.incident ? `INC-${d.incident.id} (${d.incident.category}; alerts ${d.incident.alert_ids.map((i) => "#" + i).join(", ")}) — incident ids are numbered separately from alert ids` : "none"],
      ["Detection", typeBadge(a.detection_type)], ["Category", d.category],
      ["Endpoint", `${d.risk_link.method || "any method"} ${a.endpoint}`],
      ["Caller", copyable(a.actor, el("span", { class: "mono", text: a.actor }))],
      ["Severity / risk", `${d.severity} (${a.risk_score}/100)`], ["Outcome", d.outcome],
      ["Evidence window (UTC)", md.first_seen ? `${md.first_seen} → ${md.last_seen || a.last_seen}` : null],
      ["Alert first / last seen (UTC)", `${a.first_seen} / ${a.last_seen} · seen ${a.occurrences}×`],
      ["Disposition", `${d.disposition.status}${d.disposition.note ? ` — note: ${d.disposition.note}` : ""}`],
    ]),
    el("h3", { text: d.rule ? `Rule ${d.rule.id}: ${d.rule.title}` : "Rule" }),
    el("p", { text: d.rule ? d.rule.explanation : "This alert predates rule ids; its reason below is what fired." }),
    el("p", { class: "reason", text: a.reason }),
    el("h3", { text: "Enforcement" }),
    el("div", { class: "facts" }, badge(enfLabel, enfKind)),
    el("p", { text: enf.summary }),
    enf.events.length ? makeTable("Access-control decisions for this caller", [
      { label: "Decision", cell: (e) => e.decision }, { label: "Endpoint", cls: "path", cell: (e) => e.endpoint },
      { label: "Reason", cell: (e) => e.reason }, { label: "Count", cls: "num", cell: (e) => e.count },
      { label: "Last (UTC)", cls: "nowrap", cell: (e) => timeCell(e.last_seen) },
    ], enf.events) : null,
    el("h3", { text: `Request evidence (${d.requests.length} of ${d.requests_matched} matching captured requests)` }),
    d.requests.length ? makeTable("Captured requests behind this alert", [
      { label: "Time (UTC)", cls: "nowrap", cell: (r) => timeCell(r.at) },
      { label: "Request", cls: "path", cell: (r) => `${r.method} ${r.path}` },
      { label: "Status", cls: "num", cell: (r) => r.status_code },
      { label: "Client IP", cls: "mono", cell: (r) => r.client_ip },
      { label: "Credential", cls: "mono", cell: (r) => r.credential || r.auth_type },
    ], d.requests) : stateBox("", "No captured request matches this alert's caller, endpoint and time span."),
    d.legacy ? stateBox("warn", "Stored by an earlier detector version (no rule id). Current scans update it only if they reproduce the same type, caller and endpoint; check the related alerts below for a current record of the same activity.") : null,
    d.related_by_caller && d.related_by_caller.length ? el("div", {}, el("h3", { text: "Same caller, overlapping time (all categories)" }),
      el("ul", {}, d.related_by_caller.map((r) => el("li", {},
        el("button", { class: "btn small", type: "button", text: `#${r.id}`, onclick: () => openAlertDetail(r.id) }),
        " ", typeBadge(r.detection_type), ` ${r.endpoint} · ${r.status} · INC-${r.incident_id} · shares ${r.shared.join(", ")}`,
        r.possible_duplicate ? el("span", {}, " ", badge("possible duplicate: same type and endpoint", "warn")) : null)))) : null,
    d.related_alerts.length ? el("div", {}, el("h3", { text: "Related alerts in this incident" }),
      el("ul", {}, d.related_alerts.map((r) => el("li", {},
        el("button", { class: "btn small", type: "button", text: `#${r.id}`, onclick: () => openAlertDetail(r.id) }),
        " ", typeBadge(r.detection_type), ` ${r.endpoint} · ${r.status} · risk ${r.risk_score}`)))) : null,
    el("div", { class: "controls" },
      el("button", { class: "btn small", type: "button", text: "View endpoint risk explanation",
        onclick: () => showEndpointRisk(d.risk_link.method, d.risk_link.path) })),
    el("details", { class: "more" }, el("summary", { text: "Redacted evidence, provenance and missing fields" }),
      el("p", { class: "small", text: d.provenance }),
      el("ul", { class: "small" }, d.missing_fields.map((m) => el("li", { text: m }))),
      el("pre", { class: "mono", text: JSON.stringify(md, null, 2) })));
}

/* ---------- Risk & Analytics tab: per-endpoint scores ---------- */
const riskKey = (m, p) => `${m} ${p}`;
function changeCell(e) {
  if (!e.change) return el("span", { class: "small muted", text: e.history });
  const c = e.change, arrow = c.direction === "up" ? "↑" : c.direction === "down" ? "↓" : "→";
  return el("div", {}, badge(`${arrow} ${c.delta > 0 ? "+" : ""}${c.delta}`, c.direction === "up" ? "bad" : c.direction === "down" ? "ok" : ""),
    el("div", { class: "small muted", text: `${c.previous_score} → ${c.current_score}` }));
}
function renderEndpointRisk() {
  const r = state.risk;
  if (r == null) return;
  const cov = r.coverage;
  $("risk-count").textContent = cov ? `${cov.scored} of ${cov.discovered} discovered endpoints scored · ${cov.not_scored ? `${cov.not_scored} not scored (listed below)` : "none excluded"}`
    : `${r.total} endpoints`;
  if (!r.items.length) return setBody("risk-body", stateBox("info", (r.excluded || []).length
    ? "No served endpoint to score yet: every discovered route only answered 404/405 (listed below)."
    : "No endpoint observed yet. Send traffic through the monitored API."), excludedRisk(r));
  setBody("risk-body", makeTable("Endpoint risk scores", [
    { label: "Endpoint", cls: "path", cell: (e) => `${e.method} ${e.path}` },
    { label: "Score", cls: "nowrap", cell: (e) => el("div", {}, riskCell(e.score),
      e.confidence ? el("div", { class: "small muted", title: e.confidence_reason || "", text: e.confidence }) : null) },
    { label: "Change", cell: changeCell },
    { label: "Explanation", cell: (e) => el("details", { class: "more", "data-endpoint": riskKey(e.method, e.path) },
      el("summary", { text: e.explanation }),
      makeTable(`Factors for ${e.method} ${e.path}`, [
        { label: "Factor", cell: (f) => f.factor.replace("_", " ") },
        { label: "Points", cls: "num nowrap", cell: (f) => `${f.points} / ${f.max_points}` },
        { label: "Evidence", cell: (f) => el("div", {}, f.evidence.map((x) => el("div", { text: x })),
          f.alert_ids.length ? el("div", { class: "small" }, "alerts: ", f.alert_ids.map((id) =>
            el("button", { class: "btn small", type: "button", text: `#${id}`, onclick: () => { applyTab("detection"); openAlertDetail(id); } }))) : null,
          f.unavailable ? el("div", { class: "small muted", text: `Unavailable: ${f.unavailable}` }) : null) },
      ], e.factors),
      e.change ? el("p", { class: "small", text: `Change ${e.change.previous_at} → ${e.change.current_at || "now (not yet recorded)"}: ` +
        (e.change.factors.map((f) => `${f.factor} ${f.from}→${f.to}`).join(", ") || "factor evidence changed") +
        (e.change.new_alert_ids.length ? `; new alerts ${e.change.new_alert_ids.map((i) => "#" + i).join(" ")}` : "") +
        (e.change.no_longer_counted_alert_ids.length ? `; no longer counted ${e.change.no_longer_counted_alert_ids.map((i) => "#" + i).join(" ")}` : "") }) : null) },
  ], r.items, (e) => `sev-${severity(e.score)}`),
  excludedRisk(r));
}
function excludedRisk(r) {
  return (r.excluded || []).length ? el("details", { class: "more" }, el("summary", { text: `${r.excluded.length} discovered route(s) not scored` }),
    makeTable("Discovered routes without a score", [
      { label: "Endpoint", cls: "path", cell: (e) => `${e.method} ${e.path}` },
      { label: "Requests", cls: "num", cell: (e) => e.request_count },
      { label: "Status codes", cell: (e) => e.status_codes.join(", ") },
      { label: "Why not scored", cell: (e) => el("span", { class: "reason", text: e.reason }) },
    ], r.excluded)) : null;
}
function showEndpointRisk(method, path) {
  applyTab("risk");
  const all = [...$("risk-body").querySelectorAll("details[data-endpoint]")];
  const target = all.find((d) => d.dataset.endpoint === riskKey(method, path)) || all.find((d) => d.dataset.endpoint.endsWith(` ${path}`));
  if (!target) return toast(`No risk score for ${path} yet (refresh, or the endpoint has no captured traffic).`, "info");
  target.open = true;
  target.scrollIntoView({ block: "center" });
  target.querySelector("summary").focus();
}

/* ---------- Proxy & Protection / Access & Configuration tabs ---------- */
const DECISIONS = { allowed: ["allowed", "ok"], rate_limited: ["rate limited (429)", "warn"], blocked: ["blocked", "bad"], ignored: ["claim ignored", "info"] };

/* protection-state:start — pure functions (no DOM), unit-tested by backend/tests/test_protection_state.py.
   Classified ONLY from what the backend reports: /api/rate-limits (gateway_enabled, quotas) and
   /api/gateway-events (recorded decisions). The backend exposes no upstream health check and does
   not record successful forwards, so "gateway active and healthy" cannot be confirmed and is never
   shown; nothing here turns green merely because the backend is reachable. */
const EVENT_ROW_LIMIT = 100;  // matches the ?limit= the access loader requests
const UPSTREAM_FAILURE_REASONS = ["upstream_unavailable", "upstream_timeout", "upstream_address_refused",
  "upstream_redirect", "response_too_large"];
function protectionState(access) {
  if (!access || !access.limits || !access.events) {
    return { key: "unknown", kind: "", label: "Protection status unknown",
      detail: "The access-control endpoints could not be read, so neither the gateway nor the rate limiter can be described." };
  }
  if (!access.limits.gateway_enabled) {
    return { key: "disabled", kind: "info", label: "Gateway disabled",
      detail: "No gateway configuration is loaded (SENTINEL_GATEWAY_CONFIG is not set). Traffic reaches the monitored API directly: Sentinel observes and scores it but does not filter it. This is a valid optional setup, not a fault." };
  }
  const failures = access.events.items.filter((e) => UPSTREAM_FAILURE_REASONS.includes(e.reason));
  if (failures.length) {
    const count = failures.reduce((n, e) => n + e.count, 0);
    const last = failures.map((e) => e.last_seen).sort().pop();
    return { key: "configured_errors", kind: "bad", label: "Gateway configured — upstream errors recorded",
      detail: `${count} gateway request${count === 1 ? "" : "s"} failed to reach the protected upstream (latest ${last} UTC) in the ${EVENT_ROW_LIMIT} most recent event rows. The upstream may be down or refused.`,
      failures: count, lastFailure: last };
  }
  return { key: "configured_unverified", kind: "warn", label: "Gateway configured — upstream health not confirmed",
    detail: "The backend has a gateway configuration loaded and enforces its route allowlist on /gateway/* requests, but it exposes no upstream health check, so this page cannot confirm the protected API is reachable. No upstream failures appear in the recorded events." };
}
function rateLimitState(access) {
  if (!access || !access.limits) return { key: "unknown", label: "Rate limiting: status unknown" };
  const n = access.limits.items.length;
  return { key: "configured", label: `Rate limiting: ${n} endpoint${n === 1 ? "" : "s"} with a quota per ${access.limits.window_seconds} s window` };
}
function eventSummary(access) {
  if (!access || !access.events) return "Access-control events unavailable.";
  const rows = access.events.items.length;
  if (!rows) return `No access-control events were recorded in the ${EVENT_ROW_LIMIT} most recent stored event rows. This does not mean attacks were blocked; it means nothing was recorded.`;
  const total = access.events.items.reduce((n, e) => n + e.count, 0);
  return `${total} recorded request${total === 1 ? "" : "s"} across ${rows} event row${rows === 1 ? "" : "s"} (the ${EVENT_ROW_LIMIT} most recent stored rows at most).`;
}
/* protection-state:end */

function protectionBanner(access) {
  const p = protectionState(access);
  return el("div", { class: `protect-banner ${p.kind}`.trim(), role: "status", data: { state: p.key } },
    el("div", { class: "protect-label", text: p.label }),
    el("div", { class: "protect-detail", text: p.detail }),
    el("div", { class: "protect-meta" }, badge(rateLimitState(access).label), el("span", { class: "small muted", text: eventSummary(access) })));
}
function renderAccess() {
  const acc = state.access;
  if (acc == null) return;
  const { limits, events } = acc;
  $("access-count").textContent = `${events.items.length} event rows`;
  const facts = protectionBanner(acc);
  const decisionRows = ["allowed", "rate_limited", "blocked", "ignored"].map((d) => ({
    label: (DECISIONS[d] || [d])[0],
    value: events.items.filter((e) => e.decision === d).reduce((n, e) => n + e.count, 0),
    kind: d === "allowed" ? "ok" : d === "blocked" ? "bad" : d === "rate_limited" ? "warn" : "info",
  }));
  const chart = barChart("Access-control decisions", decisionRows, { empty: "No access-control events yet." });
  const eventsPart = events.items.length ? makeTable("Access-control events", [
    { label: "Decision", cell: (e) => { const [t, k] = DECISIONS[e.decision] || [e.decision, ""]; return badge(t, k); } },
    { label: "Reason", cell: (e) => e.reason.replaceAll("_", " ") },
    { label: "Endpoint", cls: "path", cell: (e) => e.endpoint },
    { label: "Who", cell: (e) => el("div", {}, el("div", { text: e.principal_id || e.identity_kind }),
      el("div", { class: "small muted", text: `${e.role}${e.purpose !== "normal" ? ` · ${e.purpose.replace("_", " ")}` : ""} · ${e.client_ip}` })) },
    { label: "Count", cell: (e) => e.count },
    { label: "Last seen (UTC)", cls: "nowrap", cell: (e) => timeCell(e.last_seen) },
  ], events.items, (e) => (e.decision === "blocked" || e.decision === "rate_limited" ? "sev-medium" : "")) :
    stateBox("", "No access-control events yet. 429s, firewall blocks, VP use, scanner/test traffic and ignored role claims appear here.");
  setBody("access-body", facts, chart, eventsPart);
}
function renderAccessConfig() {
  if (!$("quota-body")) return;
  const acc = state.access;
  if (acc == null) return setBody("quota-body", stateBox("", "Access control data not loaded yet."));
  const { limits } = acc;
  $("quota-count").textContent = `${limits.items.length} endpoints`;
  const facts = el("div", { class: "facts" },
    badge(`VP quota = ${limits.vp_multiplier}× normal`),
    badge(`${limits.principals_configured} registered principals`),
    limits.vp_principals ? badge(`${limits.vp_principals} with VP quota`, "info")
      : badge("no VP principals configured: nobody gets the VP quota", "warn"));
  const table = makeTable("Per-endpoint quotas", [
    { label: "Endpoint", cls: "path", cell: (i) => i.endpoint },
    { label: "Normal / window", cell: (i) => i.normal_limit },
    { label: `VP (${limits.vp_multiplier}×)`, cell: (i) => i.vp_limit },
    { label: "Source", cell: (i) => i.source },
  ], limits.items);
  setBody("quota-body", facts, table);
}

/* ---------- Evaluation tab ----------
   Real accuracy numbers only: GET /api/evaluation reads whatever the backend last computed by
   actually running its own labelled benchmark (backend/benchmark/) against the real, unmodified
   detection pipeline in an isolated subprocess — never fabricated here, never inferred from live
   alerts (an alert alone proves nothing about ground truth). Before the first "Run evaluation"
   click in this backend process, available=false and nothing is shown as if it were a result. */
function fmtPct(v) { return v == null ? "Not measured" : `${(v * 100).toFixed(1)}%`; }
function fmtRatio(v) { return v == null ? "Not measured" : v.toFixed(2); }

// One evaluation set: the two headline rates with their real formula and denominator,
// then the labelled confusion matrix they were computed from.
function metricCard(title, m, sub, variant) {
  const card = el("article", { class: `metric-card ${variant || ""}`.trim(), "aria-label": title });
  card.append(el("h3", { class: "metric-title", text: title }));
  if (!m) {
    card.append(el("p", { class: "muted", text: "Not measured" }));
    return card;
  }
  const stat = (name, value, formula) => el("div", { class: "metric-stat" },
    el("div", { class: "metric-name", text: name }),
    el("div", { class: "metric-big", text: value }),
    el("div", { class: "metric-formula", text: formula }));
  card.append(el("div", { class: "metric-head" },
    stat("Recall (detection rate)", fmtPct(m.recall), `TP / (TP + FN) = ${m.tp} / ${m.tp + m.fn}`),
    stat("False-positive rate", fmtPct(m.false_positive_rate), `FP / (FP + TN) = ${m.fp} / ${m.fp + m.tn}`)));
  const cell = (label, value, kind) => el("div", { class: `cm-cell ${kind}`.trim() },
    el("span", { class: "cm-label", text: label }), el("span", { class: "cm-value", text: String(value) }));
  card.append(el("div", { class: "cm-grid", role: "group", "aria-label": `${title} confusion matrix` },
    cell("True positives", m.tp, "ok"), cell("False negatives", m.fn, "warn"),
    cell("False positives", m.fp, "bad"), cell("True negatives", m.tn, "")));
  card.append(el("div", { class: "facts" },
    badge(`precision ${fmtPct(m.precision)}`), badge(`F1 ${fmtRatio(m.f1)}`)));
  if (sub) card.append(el("p", { class: "metric-sub", text: sub }));
  return card;
}

async function loadEvaluationStatus() {
  try {
    state.evaluation = await api("GET", "/api/evaluation");
  } catch (err) {
    state.evaluation = { available: false, note: `Could not check evaluation status: ${err.message}` };
  }
  renderEvaluation();
}

function renderEvaluation() {
  if (!$("evaluation-body")) return;
  const r = state.evaluation;
  if (!r) return setBody("evaluation-body", stateBox("", "Checking…"));
  if (!r.available) {
    setBody("evaluation-body", stateBox("info", r.note),
      el("p", { class: "small muted" },
        "Runs the project's own ground-truth-labelled benchmark (backend/benchmark/) against the real, " +
        "unmodified capture → analyze → score → alert pipeline, in an isolated subprocess with its " +
        "own temporary database — never the live one and never inferred from live alerts. Takes a few " +
        "seconds. Press “Run evaluation” above."));
    return;
  }
  const parts = [];
  parts.push(el("div", { class: "facts" },
    badge(`seed ${r.seed}`), badge(`${r.total_instances} labelled instances`, "info"),
    badge(`${r.total_records} synthetic records`), badge(`${r.duration_ms} ms run time`),
    r.persisted ? badge("saved \u2014 survives a backend restart", "ok") : badge("not saved \u2014 lost on restart", "warn")),
    r.persisted ? null : el("p", { class: "small muted", text: r.note }),
    el("div", { class: "small muted" }, "Last run: ", timeCell(r.ran_at)),
    el("p", { class: "small muted" },
      "Synthetic-benchmark accuracy only, not a measurement of live production accuracy. Ground truth comes " +
      "from the scenario author’s labels, never inferred from an alert alone."));
  parts.push(el("div", { class: "eval-cards" },
    metricCard("Overall", r.overall, "All scenarios; unit = labelled instance × detection type.", "overall"),
    metricCard("Tuning set (in-sample)", r.tuning_set, "Scenarios the detectors were tuned on.", "tuning"),
    metricCard("Holdout set", r.holdout_set, "Never tuned on — the more honest estimate of the two.", "holdout")));
  const typeRows = Object.entries(r.per_detection_type).map(([t, m]) => ({
    label: (TYPE_LABELS[t] || [t])[0], value: m.recall == null ? 0 : Math.round(m.recall * 100),
    kind: m.recall == null ? "" : m.recall >= 0.7 ? "ok" : m.recall >= 0.4 ? "warn" : "bad",
  }));
  parts.push(barChart("Recall by detection type (%, all scenarios)", typeRows,
    { subtitle: "0% is shown for types with no eligible positive case (“Not measured” above).",
      empty: "No detection types evaluated." }));
  // Holdout scenarios first: they are the stronger signal and the ones a reviewer looks for.
  const ordered = [...r.scenarios].sort((a, b) => Number(b.holdout) - Number(a.holdout));
  parts.push(el("section", { class: "eval-table", "aria-labelledby": "eval-scenarios-h" },
    el("h3", { id: "eval-scenarios-h", text: `Abuse-scenario results (${r.scenarios.length} scenarios)` }),
    makeTable("Abuse-scenario results", [
      { label: "Scenario", cls: "scenario", cell: (s) => el("div", {},
        el("div", { class: "mono", text: s.name }), el("div", { class: "small muted", text: s.description })) },
      { label: "Set", cls: "nowrap", cell: (s) => (s.holdout ? badge("holdout", "warn") : badge("tuning", "info")) },
      { label: "Expected detection", cell: (s) => s.expected.join(", ") || "none (legitimate traffic)" },
      { label: "Instances", cls: "num", cell: (s) => s.instances },
      { label: "Hits", cls: "num", cell: (s) => badge(s.hits, s.hits ? "ok" : "") },
      { label: "Misses", cls: "num", cell: (s) => badge(s.misses, s.misses ? "bad" : "") },
      { label: "False alerts", cls: "num", cell: (s) => badge(s.false_alerts, s.false_alerts ? "warn" : "") },
      { label: "Detection rate", cls: "num nowrap", cell: (s) => fmtPct(s.detection_rate) },
      { label: "False-alert rate", cls: "num nowrap", cell: (s) => fmtPct(s.false_alert_rate) },
    ], ordered, (s) => (s.misses || s.false_alerts ? "sev-medium" : ""))));
  parts.push(el("p", { class: "small muted" },
    "Every scenario listed executed as part of this run: the benchmark has no partial-failure mode, so a " +
    "visible result here means it ran to completion. “Hits” / “Misses” / “False alerts” is the " +
    "detection outcome — whether the real detectors agreed with that scenario’s expected ground truth — " +
    "not a measure of execution success."));
  if (r.shadow_api) {
    const s = r.shadow_api;
    parts.push(el("section", { class: "panel" }, el("header", {}, el("h3", { text: "Shadow-API detection" })),
      el("div", { class: "body" },
        el("div", { class: "facts" }, badge(`precision ${fmtPct(s.precision)}`), badge(`recall ${fmtPct(s.recall)}`)),
        s.false_positives.length ? el("p", { class: "small" },
          `False positives: ${s.false_positives.map((p) => p.join(" ")).join(", ")}`) : null,
        s.missed.length ? el("p", { class: "small" },
          `Missed: ${s.missed.map((p) => p.join(" ")).join(", ")}`) : null)));
  }
  if (r.unattributed_alerts) parts.push(el("p", { class: "small muted" },
    `${r.unattributed_alerts} alert(s) in this run matched no labelled test actor and were counted as false positives.`));
  parts.push(el("p", { class: "small muted" }, r.test_execution_coverage));
  setBody("evaluation-body", ...parts.filter(Boolean));
}

/* ---------- tabs ---------- */
function applyTab(tab) {
  if (!TABS.includes(tab)) tab = "overview";
  state.tab = tab;
  for (const panel of document.querySelectorAll("[data-tab-panel]")) {
    panel.hidden = panel.dataset.tabPanel !== tab;
  }
  for (const btn of document.querySelectorAll(".nav-btn")) {
    const active = btn.dataset.tab === tab;
    if (active) btn.setAttribute("aria-current", "page"); else btn.removeAttribute("aria-current");
  }
  try { localStorage.setItem("sentinel-tab", tab); } catch (err) { /* private browsing: ignore */ }
}
function wireTabs() {
  const buttons = [...document.querySelectorAll(".nav-btn")];
  buttons.forEach((btn, i) => {
    btn.addEventListener("click", () => applyTab(btn.dataset.tab));
    btn.addEventListener("keydown", (e) => {
      if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
      e.preventDefault();
      const next = buttons[(i + (e.key === "ArrowDown" ? 1 : -1) + buttons.length) % buttons.length];
      next.focus(); applyTab(next.dataset.tab);
    });
  });
  let saved = "overview";
  try { saved = localStorage.getItem("sentinel-tab") || "overview"; } catch (err) { /* ignore */ }
  applyTab(saved);
}

/* ---------- density ---------- */
function wireDensity() {
  const select = $("density");
  if (!select) return;
  let saved = "comfortable";
  try { saved = localStorage.getItem("sentinel-density") || "comfortable"; } catch (err) { /* ignore */ }
  document.body.dataset.density = saved;
  select.value = saved;
  select.addEventListener("change", () => {
    document.body.dataset.density = select.value;
    try { localStorage.setItem("sentinel-density", select.value); } catch (err) { /* private browsing: ignore */ }
  });
}

/* ---------- loading ---------- */
// Public health says the backend is up; the proxy's status probe says whether
// a protected read is accepted. Unknown probe results do not downgrade the pill.
// Returns { auth, revision }; revision 0 = a proxy too old to report one.
async function loadProxyStatus() {
  try {
    const res = await fetch("/api/proxy-status", { cache: "no-store" });
    if (res.status === 404) return { auth: "unknown", revision: 0 };
    const body = res.ok ? await res.json() : null;
    if (!body) return { auth: "unknown", revision: null };
    return { auth: body.backend || "unknown", revision: Number(body.proxy_revision) || 0 };
  } catch (err) {
    return { auth: "unknown", revision: null };
  }
}
function versionProblem(backendRevision, proxyRevision) {
  const stale = [];
  if ((Number(backendRevision) || 1) < REQUIRED_API_REVISION) stale.push("the backend (uvicorn)");
  if (proxyRevision != null && proxyRevision < REQUIRED_PROXY_REVISION) stale.push("the dashboard proxy (demo/serve.py)");
  return stale.length ? `Version mismatch: ${stale.join(" and ")} ${stale.length > 1 ? "are" : "is"} running older code than this page. Restart ${stale.length > 1 ? "them" : "it"} from the updated source (scripts/run-local.sh).` : "";
}
// Resolves to "ok", "auth_failed", "mismatch" or "unreachable".
async function loadHealth() {
  const conn = $("conn");
  try {
    const res = await fetch("/api/health", { cache: "no-store" });
    const body = await res.json().catch(() => null);
    if (res.status === 502 || !body) throw new Error("unreachable");
    const ok = res.ok && body.status === "ok";
    const proxy = ok ? await loadProxyStatus() : { auth: "unknown", revision: null };
    const auth = proxy.auth;
    $("conn-detail").textContent = `${body.service || "api-sentinel"} v${body.version || "?"} · API rev ${body.api_revision || 1} · database ${body.database || "?"}`;
    const mismatch = ok ? versionProblem(body.api_revision, proxy.revision) : "";
    if (mismatch) {
      conn.className = "conn warn";
      $("conn-text").textContent = "Version mismatch";
      $("conn-detail").textContent = mismatch;
      state.mismatch = mismatch;
      return "mismatch";
    }
    state.mismatch = "";
    if (auth === "auth_failed") {
      conn.className = "conn bad";
      $("conn-text").textContent = AUTH_FAILED_TEXT;
      $("conn-detail").textContent = "backend is reachable; protected sections are refused";
      return "auth_failed";
    }
    conn.className = `conn ${ok ? "ok" : "warn"}`;
    $("conn-text").textContent = ok ? "Backend connected" : "Backend degraded";
    return "ok";
  } catch (err) {
    conn.className = "conn bad";
    $("conn-text").textContent = "Backend unreachable";
    $("conn-detail").textContent = "check that uvicorn is running";
    return "unreachable";
  }
}
async function loadSection(name, fetcher, assign, render, bodyId) {
  markBusy(bodyId);
  try {
    assign(await fetcher());
    render();
  } catch (err) {
    markUnavailable(name);
    setBody(bodyId, stateBox("bad", `Could not load this section. ${err.message}`, () => reloadOne(name)));
  }
  renderCards();
  renderOverview();
}
const loaders = {
  inventory: () => loadSection("inventory", () => api("GET", "/api/inventory"), (v) => { state.inventory = v; },
    () => { renderInventory(); renderMonitoringChart(); renderSource(); }, "inventory-body"),
  history: () => loadSection("history", () => api("GET", "/api/runtime/history"), (v) => { state.history = v; }, renderHistory, "history-body"),
  risk: () => loadSection("risk", () => api("GET", "/api/risk/endpoints"), (v) => { state.risk = v; },
    () => { renderEndpointRisk(); renderInventory(); }, "risk-body"),
  baselines: () => loadSection("baselines", async () => {
    try {
      return await api("GET", "/api/runtime/baselines");
    } catch (err) {
      if (state.mismatch) throw new Error(state.mismatch);  // stale backend/proxy: name the real cause
      throw err;
    }
  }, (v) => { state.baselines = v; }, renderBaselines, "baselines-body"),
  shadow: () => {
    const spec = $("spec").value.trim();
    const url = "/api/shadow-apis" + (spec ? `?spec_path=${encodeURIComponent(spec)}` : "");
    return loadSection("shadow", () => api("GET", url), (v) => { state.shadow = v; }, () => { renderShadow(); renderInventory(); }, "shadow-body");
  },
  findings: () => loadSection("findings", async () => (await api("GET", "/api/findings")).items, (v) => { state.findings = v; }, renderFindings, "findings-body"),
  alerts: () => loadSection("alerts", async () => (await api("GET", "/api/alerts")).items, (v) => { state.alerts = v; },
    () => {
      renderAlerts(); renderDetectionCharts(); renderRisk();
      if (state.detailId != null && !$("alert-detail").hidden) openAlertDetail(state.detailId, false);  // keep it current
    }, "alerts-body"),
  access: () => loadSection("access", async () => {
    try {
      const [limits, events] = await Promise.all([api("GET", "/api/rate-limits"), api("GET", "/api/gateway-events?limit=" + EVENT_ROW_LIMIT)]);
      return { limits, events };
    } catch (err) {
      // A backend or dashboard proxy started before these endpoints existed answers 404 (backend)
      // or 401 (proxy that does not attach the key to them). Say so instead of a bare status.
      if (state.mismatch) throw new Error(state.mismatch);  // e.g. an old proxy answers 401: name the real cause
      if (err.status === 404) {
        throw new Error("This backend does not provide /api/rate-limits or /api/gateway-events. It is running code from before access control was added; restart it (and the dashboard proxy) from the updated source.");
      }
      throw err;
    }
  }, (v) => { state.access = v; }, () => { renderAccess(); renderAccessConfig(); }, "access-body"),
};
function reloadOne(name) { return loaders[name](); }

async function refreshAll() {
  const health = await loadHealth();
  if (health === "unreachable") {
    for (const name of SECTIONS) {
      markUnavailable(name);
      setBody(`${name}-body`, stateBox("bad", "The backend is unreachable, so this section cannot be loaded.", () => runOp("refresh")));
    }
    state.evaluation = { available: false, note: "Backend unreachable." };
    renderEvaluation();
    renderCards();
    renderOverview();
    return health;
  }
  // Evaluation status is a cheap GET (reads what was last computed; never re-runs the benchmark
  // itself), so it is safe to check on every refresh alongside the other sections.
  await Promise.all([...Object.values(loaders).map((load) => load()), loadEvaluationStatus()]);
  const failed = SECTIONS.filter((name) => state[name] === null).length;
  $("last-refresh").textContent = `Last refresh ${new Date().toLocaleTimeString()} (your local time)` +
    (failed ? ` · ${failed} section${failed === 1 ? "" : "s"} failed` : "");
  return health;
}

/* ---------- actions (one at a time) ---------- */
const OP_BUTTONS = ["btn-refresh", "btn-traffic", "btn-scan", "btn-evaluate"];
async function runOp(name) {
  if (state.busy) return;
  state.busy = true;
  const buttonId = { refresh: "btn-refresh", traffic: "btn-traffic", scan: "btn-scan", evaluate: "btn-evaluate" }[name];
  for (const id of OP_BUTTONS) $(id).disabled = true;
  $(buttonId).setAttribute("aria-busy", "true");
  try {
    await ops[name]();
  } finally {
    state.busy = false;
    $(buttonId).removeAttribute("aria-busy");
    for (const id of OP_BUTTONS) $(id).disabled = false;
  }
}
const ops = {
  async refresh() {
    setOpStatus("Refreshing…");
    const health = await refreshAll();
    // The status line must agree with the section cards, so count what failed.
    const failed = SECTIONS.filter((name) => state[name] === null).length;
    if (health === "unreachable") setOpStatus("Backend unreachable.", "bad");
    else if (health === "auth_failed") setOpStatus(AUTH_FAILED_TEXT + ".", "bad");
    else if (health === "mismatch") setOpStatus(state.mismatch, "bad");
    else if (failed) setOpStatus(`Refreshed, but ${failed} section${failed === 1 ? "" : "s"} could not load.`, "bad");
    else setOpStatus("Refreshed.", "ok");
  },
  async traffic() {
    const plan = JSON.parse($("sample-traffic").textContent);
    setOpStatus(`Sending ${plan.length} sample requests to the demo shop…`);
    let codes;
    try {
      codes = await Promise.all(plan.map((step) => fetch(step.path,
        step.token ? { headers: { Authorization: `Bearer ${step.token}` }, cache: "no-store" } : { cache: "no-store" })
        .then((r) => r.status)));
    } catch (err) {
      setOpStatus("Sample traffic failed: the dashboard proxy is unreachable.", "bad");
      toast("Sample traffic failed: the dashboard proxy is unreachable.", "bad");
      return;
    }
    await refreshAll();
    if (codes.every((c) => c === 404)) {
      const msg = `The demo shop is not mounted on this backend (all ${codes.length} sample requests returned 404). Start the backend with ENABLE_DEMO_TARGET=true (development only; e.g. in the env file for scripts/run-local.sh).`;
      setOpStatus(msg, "bad"); toast(msg, "bad");
      return;
    }
    const tally = {};
    for (const c of codes) tally[c] = (tally[c] || 0) + 1;
    const summary = Object.entries(tally).map(([c, n]) => `${n}×${c}`).join(", ");
    setOpStatus(`Sent ${plan.length} requests (${summary}). Press Run scan to store alerts.`, "ok");
    toast(`Sample traffic sent: ${summary}.`, "ok");
  },
  async scan() {
    setOpStatus("Scanning captured traffic…");
    try {
      const r = await api("POST", "/api/scan", {});
      const msg = `Scan complete: ${r.findings} findings · ${r.created} new · ${r.updated} updated · ${r.unchanged} unchanged.`;
      setOpStatus(msg, "ok"); toast(msg, "ok");
      await refreshAll();  // traffic may have arrived from outside the page, so reload every section
    } catch (err) {
      setOpStatus(`Scan failed. ${err.message}`, "bad");
      toast(`Scan failed. ${err.message}`, "bad");
    }
  },
  async evaluate() {
    setOpStatus("Running the labelled benchmark (isolated subprocess, a few seconds)…");
    try {
      const r = await api("POST", "/api/evaluation", {});
      state.evaluation = r;
      renderEvaluation();
      const msg = `Evaluation complete: ${r.total_instances} labelled instances, overall F1 ${fmtRatio(r.overall.f1)}.`;
      setOpStatus(msg, "ok"); toast(msg, "ok");
    } catch (err) {
      setOpStatus(`Evaluation failed. ${err.message}`, "bad");
      toast(`Evaluation failed. ${err.message}`, "bad");
    }
  },
};

/* ---------- wiring ---------- */
$("btn-refresh").addEventListener("click", () => runOp("refresh"));
$("btn-traffic").addEventListener("click", () => runOp("traffic"));
$("btn-evaluate").addEventListener("click", () => runOp("evaluate"));
$("btn-scan").addEventListener("click", () => runOp("scan"));
$("btn-spec").addEventListener("click", () => loaders.shadow());
$("btn-spec-reset").addEventListener("click", () => { $("spec").value = ""; loaders.shadow(); });
$("spec").addEventListener("keydown", (e) => { if (e.key === "Enter") loaders.shadow(); });
$("inv-search").addEventListener("input", (e) => { state.invFilter = e.target.value; renderInventory(); });
$("inv-method").addEventListener("change", (e) => { state.invMethod = e.target.value; renderInventory(); });
$("btn-src-load").addEventListener("click", loadSource);
for (const [id, key, ev] of [["alert-type", "alertType", "change"], ["alert-sev", "alertSev", "change"], ["alert-time", "alertTime", "change"], ["alert-q", "alertQ", "input"]]) {
  $(id).addEventListener(ev, (e) => { state[key] = e.target.value; renderAlerts(); });
}
$("btn-detail-close").addEventListener("click", () => { $("alert-detail").hidden = true; state.detailId = null; });
$("src-project").addEventListener("keydown", (e) => { if (e.key === "Enter") loadSource(); });
$("btn-src-scan").addEventListener("click", scanSource);
$("src-type").addEventListener("change", syncSourceInputs);
syncSourceInputs();
$("auto").addEventListener("change", (e) => {
  clearInterval(state.timer);
  if (e.target.checked) {
    state.timer = setInterval(() => {
      const editing = document.activeElement && document.activeElement.closest && document.activeElement.closest(".triage");
      // A refresh during a Save could re-render the alert from a pre-save read.
      const saving = document.querySelector("[data-alert-save][aria-busy]");
      if (!state.busy && !document.hidden && !editing && !saving) refreshAll();
    }, AUTO_REFRESH_MS);
  }
});
wireTabs();
wireDensity();
renderEvaluation();

renderCards();
renderOverview();
renderFilterChips();
runOp("refresh");
