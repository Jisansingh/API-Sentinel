"use strict";
/* API Sentinel demo dashboard. Plain DOM, no framework, no network access except
   same-origin /api/* and /shop/* through the local proxy. Everything that comes
   from the backend or from captured traffic is inserted with textContent / text
   nodes only: this file never builds HTML from strings. */

const AUTO_REFRESH_MS = 15000;
// The backend and the proxy load their code at start-up; this page is read from disk on
// every request. These must match app/config.py API_REVISION and serve.py PROXY_REVISION,
// so a process started from older code is reported instead of failing piecemeal.
const REQUIRED_API_REVISION = 2;
const REQUIRED_PROXY_REVISION = 2;
const ALERT_STATUSES = ["open", "acknowledged", "resolved", "ignored"];
const TYPE_LABELS = {
  scraping: ["Scraping", "info"],
  bola_enumeration: ["BOLA enumeration (attempt)", "warn"],
  bola: ["BOLA (confirmed)", "bad"],
  token_replay: ["Token replay", "bad"],
};

const state = {
  alerts: null, findings: null, inventory: null, shadow: null, access: null,
  alertFilter: "all", invFilter: "", busy: false, timer: null,
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
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(payload);
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
  body.removeAttribute("aria-busy");
  body.replaceChildren(...children);
}
const COUNT_IDS = { alerts: "alerts-count", findings: "findings-count", shadow: "shadow-count", inventory: "inventory-count", access: "access-count" };
const SECTIONS = Object.keys(COUNT_IDS);
function markUnavailable(name) {
  state[name] = null;
  $(COUNT_IDS[name]).textContent = "unavailable";
  if (name === "alerts") renderFilterChips();
}
function markBusy(id) {
  const body = $(id);
  if (body.childElementCount) body.setAttribute("aria-busy", "true");
  else body.replaceChildren(el("div", { class: "state", text: "Loading…" }));
}

/* ---------- tables ---------- */
function makeTable(caption, columns, rows, rowClass) {
  const head = el("tr", {}, columns.map((c) => el("th", { scope: "col", text: c.label })));
  const body = rows.map((row) => el("tr", { class: rowClass ? rowClass(row) : "" },
    columns.map((c) => {
      const content = c.cell(row);
      return el("td", { class: c.cls || "", "data-label": c.label },
        content instanceof Node ? content : String(content ?? ""));
    })));
  return el("div", { class: "table-wrap", tabIndex: 0, role: "region", "aria-label": caption },
    el("table", {}, el("caption", { text: caption }), el("thead", {}, head), el("tbody", {}, body)));
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
];
function evidence(item) {
  const md = item.metadata || {};
  const facts = FACTS.filter(([key]) => md[key] != null && md[key] !== "").map(([key, fmt]) => badge(fmt(md[key])));
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
      el("pre", { class: "mono", text: detailText })));
}

/* ---------- sections ---------- */
function renderCards() {
  const alerts = state.alerts, inv = state.inventory, sh = state.shadow, fin = state.findings;
  const open = alerts ? alerts.filter((a) => a.status === "open") : null;
  const top = open && open.length ? Math.max(...open.map((a) => a.risk_score)) : null;
  const cards = [
    ["Endpoints observed", inv ? inv.total_endpoints : "—", inv ? `${inv.total_requests} requests captured` : "unavailable"],
    ["Shadow APIs", sh ? (sh.spec_loaded ? sh.shadow_apis.length : "n/a") : "—",
      sh ? (sh.spec_loaded ? `${sh.documented.length} documented routes seen` : "no specification loaded") : "unavailable"],
    ["Live findings", fin ? fin.length : "—", "rolling windows, not stored"],
    ["Open alerts", open ? open.length : "—", alerts ? `${alerts.length} stored in total` : "unavailable"],
    ["Highest open risk", top == null ? "—" : top, top == null ? (alerts ? "no open alerts" : "unavailable") : severity(top)],
  ];
  $("cards").replaceChildren(...cards.map(([label, value, sub], i) =>
    el("div", { class: `card${i === 4 ? " alert-card" : ""}` },
      el("div", { class: "label", text: label }),
      el("div", { class: `value${i === 4 && top >= 70 ? " high" : ""}`, text: String(value) }),
      el("div", { class: "sub", text: sub }))));
}

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
  const shown = state.alerts.filter((a) => state.alertFilter === "all" || a.status === state.alertFilter);
  $("alerts-count").textContent = `${shown.length} shown of ${state.alerts.length}`;
  if (!state.alerts.length) {
    return setBody("alerts-body", stateBox("info", "No stored alerts yet. Generate sample traffic, then press Run scan."));
  }
  if (!shown.length) return setBody("alerts-body", stateBox("", `No ${state.alertFilter} alerts.`));
  setBody("alerts-body", makeTable("Persistent alerts", [
    { label: "Risk", cls: "nowrap", cell: (a) => riskCell(a.risk_score) },
    { label: "Detection", cell: (a) => el("div", {}, typeBadge(a.detection_type), el("div", { class: "small muted", text: `#${a.id}` })) },
    { label: "Endpoint", cls: "path", cell: (a) => a.endpoint },
    { label: "Actor", cls: "nowrap mono", cell: (a) => el("span", { title: a.actor, text: short(a.actor, 16) }) },
    { label: "Why it fired", cell: evidence },
    { label: "Activity", cls: "nowrap", cell: (a) => el("div", {},
      el("div", { text: `seen ${a.occurrences}×` }),
      el("div", { class: "small muted" }, "first ", timeCell(a.first_seen)),
      el("div", { class: "small muted" }, "last ", timeCell(a.last_seen))) },
    { label: "Triage", cell: triageControl },
  ], shown, (a) => `sev-${severity(a.risk_score)}`));
}

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
  $("shadow-count").textContent = `${sh.shadow_apis.length} undocumented · ${sh.documented.length} documented`;
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
  setBody("shadow-body", ...parts);
}

function specStatus(row) {
  const sh = state.shadow;
  if (!sh || !sh.spec_loaded) return badge("no spec", "");
  const key = `${row.method} ${row.path}`;
  if (sh.shadow_apis.some((r) => `${r.method} ${r.path}` === key)) return badge("shadow", "bad");
  if (sh.documented.some((r) => `${r.method} ${r.path}` === key)) return badge("documented", "ok");
  return badge("404/405 only", "");
}
function renderInventory() {
  if (state.inventory == null) return;
  const inv = state.inventory;
  const q = state.invFilter.trim().toLowerCase();
  const rows = inv.items.filter((r) => !q || `${r.method} ${r.path}`.toLowerCase().includes(q));
  $("inventory-count").textContent = `${rows.length} of ${inv.total_endpoints} endpoints · ${inv.total_requests} requests`;
  if (!inv.items.length) return setBody("inventory-body", stateBox("info", "Nothing has been captured yet. Send traffic through the monitored API (or press Generate sample traffic)."));
  if (!rows.length) return setBody("inventory-body", stateBox("", "No endpoints match the filter."));
  setBody("inventory-body", makeTable("API inventory", [
    { label: "Method", cls: "method nowrap", cell: (r) => r.method },
    { label: "Path", cls: "path", cell: (r) => r.path },
    { label: "Spec", cell: specStatus },
    { label: "Requests", cell: (r) => r.request_count },
    { label: "Status codes", cell: (r) => el("div", { class: "facts" }, r.status_codes.map((c) =>
      badge(c, c < 300 ? "ok" : c < 400 ? "info" : c < 500 ? "warn" : "bad"))) },
    { label: "Last seen (UTC)", cls: "nowrap", cell: (r) => timeCell(r.last_seen) },
    { label: "Query parameters", cls: "path", cell: (r) => r.query_params.join(", ") || "—" },
  ], rows));
}

const DECISIONS = { allowed: ["allowed", "ok"], rate_limited: ["rate limited (429)", "warn"], blocked: ["blocked", "bad"], ignored: ["claim ignored", "info"] };
function renderAccess() {
  const acc = state.access;
  if (acc == null) return;
  const { limits, events } = acc;
  $("access-count").textContent = `${limits.items.length} endpoints · ${events.items.length} event rows`;
  const facts = el("div", { class: "facts" },
    badge(`window ${limits.window_seconds} s`), badge(`VP quota = ${limits.vp_multiplier}× normal`),
    badge(limits.gateway_enabled ? "gateway on" : "gateway off", limits.gateway_enabled ? "ok" : ""),
    badge(`${limits.principals_configured} registered principals`),
    limits.vp_principals ? badge(`${limits.vp_principals} with VP quota`, "info")
      : badge("no VP principals configured: nobody gets the VP quota", "warn"));
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
  setBody("access-body", facts, eventsPart,
    el("details", { class: "more" }, el("summary", { text: `Per-endpoint quotas (${limits.items.length})` }),
      makeTable("Per-endpoint quotas", [
        { label: "Endpoint", cls: "path", cell: (i) => i.endpoint },
        { label: "Normal / window", cell: (i) => i.normal_limit },
        { label: `VP (${limits.vp_multiplier}×)`, cell: (i) => i.vp_limit },
        { label: "Source", cell: (i) => i.source },
      ], limits.items)));
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
}
const loaders = {
  inventory: () => loadSection("inventory", () => api("GET", "/api/inventory"), (v) => { state.inventory = v; }, renderInventory, "inventory-body"),
  shadow: () => {
    const spec = $("spec").value.trim();
    const url = "/api/shadow-apis" + (spec ? `?spec_path=${encodeURIComponent(spec)}` : "");
    return loadSection("shadow", () => api("GET", url), (v) => { state.shadow = v; }, () => { renderShadow(); renderInventory(); }, "shadow-body");
  },
  findings: () => loadSection("findings", async () => (await api("GET", "/api/findings")).items, (v) => { state.findings = v; }, renderFindings, "findings-body"),
  alerts: () => loadSection("alerts", async () => (await api("GET", "/api/alerts")).items, (v) => { state.alerts = v; }, renderAlerts, "alerts-body"),
  access: () => loadSection("access", async () => {
    try {
      const [limits, events] = await Promise.all([api("GET", "/api/rate-limits"), api("GET", "/api/gateway-events?limit=100")]);
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
  }, (v) => { state.access = v; }, renderAccess, "access-body"),
};
function reloadOne(name) { return loaders[name](); }

async function refreshAll() {
  const health = await loadHealth();
  if (health === "unreachable") {
    for (const name of SECTIONS) {
      markUnavailable(name);
      setBody(`${name}-body`, stateBox("bad", "The backend is unreachable, so this section cannot be loaded.", () => runOp("refresh")));
    }
    renderCards();
    return health;
  }
  await Promise.all(Object.values(loaders).map((load) => load()));
  const failed = SECTIONS.filter((name) => state[name] === null).length;
  $("last-refresh").textContent = `Last refresh ${new Date().toLocaleTimeString()} (your local time)` +
    (failed ? ` · ${failed} section${failed === 1 ? "" : "s"} failed` : "");
  return health;
}

/* ---------- actions (one at a time) ---------- */
const OP_BUTTONS = ["btn-refresh", "btn-traffic", "btn-scan"];
async function runOp(name) {
  if (state.busy) return;
  state.busy = true;
  const buttonId = { refresh: "btn-refresh", traffic: "btn-traffic", scan: "btn-scan" }[name];
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
};

/* ---------- wiring ---------- */
$("btn-refresh").addEventListener("click", () => runOp("refresh"));
$("btn-traffic").addEventListener("click", () => runOp("traffic"));
$("btn-scan").addEventListener("click", () => runOp("scan"));
$("btn-spec").addEventListener("click", () => loaders.shadow());
$("btn-spec-reset").addEventListener("click", () => { $("spec").value = ""; loaders.shadow(); });
$("spec").addEventListener("keydown", (e) => { if (e.key === "Enter") loaders.shadow(); });
$("inv-search").addEventListener("input", (e) => { state.invFilter = e.target.value; renderInventory(); });
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

renderCards();
renderFilterChips();
runOp("refresh");
