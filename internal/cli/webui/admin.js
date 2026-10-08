/* ReconX dashboard: Monitoring (scheduled passive scans + alerts) and
 * Settings (API keys). Uses helpers from index.html: esc, TOKEN, toast,
 * fmtFull, fmtDate, fmtTime, ago.
 */
let MON = { list: [], rules: [], scheduler: false, alerts: [], filter: "", timer: null };

function api(path, body) {
  return fetch(path, { method: "POST", headers: { "Content-Type": "application/json", "X-ReconX-Token": TOKEN }, body: body ? JSON.stringify(body) : undefined })
    .then(async r => { if (!r.ok) throw new Error((await r.text()).trim() || `HTTP ${r.status}`); return r.status === 204 ? null : r.json(); });
}

const SEV_CLS = { high: "sev-high", medium: "sev-medium", low: "sev-low", info: "sev-info" };

/* ───────── Monitoring page ───────── */
async function showMonitoring() {
  await loadMonitoring();
  clearInterval(MON.timer);
  // Keep last-run status and alerts fresh while the page is open.
  MON.timer = setInterval(() => { if (!document.getElementById("view-monitor").classList.contains("hidden")) loadMonitoring(true); else clearInterval(MON.timer); }, 10000);
}

async function loadMonitoring(quiet) {
  try {
    const [m, a] = await Promise.all([fetch("/api/monitors").then(r => r.json()), fetch("/api/alerts?limit=200").then(r => r.json())]);
    MON.list = m.monitors || []; MON.rules = m.rules || []; MON.scheduler = !!m.scheduler; MON.alerts = a || [];
  } catch (e) { if (!quiet) toast("Could not load monitors"); return; }
  renderMonitors(); renderAlerts(); renderAlertCard();
  if (!document.getElementById("monRules").dataset.ready) {
    document.getElementById("monRules").innerHTML = MON.rules.map(r => `<label class="ck"><input type="checkbox" value="${esc(r.ID)}" checked> <span><b>${esc(r.ID.replace(/_/g, " "))}</b> <small style="color:#6f6a52">— ${esc(r.Description)}</small></span></label>`).join("");
    document.getElementById("monRules").dataset.ready = "1";
  }
}

function renderMonitors() {
  document.getElementById("monSched").innerHTML = MON.scheduler
    ? `<span class="dot ok"></span>Scheduler running — due monitors scan while this dashboard server is up.`
    : `<span class="dot no"></span>Scheduler off (<code>--no-monitor</code>). Use “Run now”, or schedule <code>reconx monitor run</code> with Task Scheduler / cron.`;
  const rows = document.getElementById("monRows");
  if (!MON.list.length) { rows.innerHTML = `<tr><td colspan="7" class="muted">No monitors yet — add a domain on the left.</td></tr>`; return; }
  rows.innerHTML = MON.list.map(m => {
    const st = m.last_status === "running" ? `<span class="tag sev-medium">scanning…</span>`
      : m.last_status === "error" ? `<span class="tag sev-high" title="${esc(m.last_error || "")}">error</span>`
      : m.last_status === "ok" ? `<span class="tag lc-active">ok</span>` : `<span class="tag lc-hist">pending</span>`;
    const last = m.last_run && !String(m.last_run).startsWith("0001") ? `<b>${fmtDate(m.last_run)}</b><span>${fmtTime(m.last_run)} · ${ago(m.last_run)}</span>` : `<b>never</b>`;
    const next = !m.enabled ? `<span class="muted">paused</span>` : (new Date(m.next_run) <= new Date() ? `<span class="muted">due now</span>` : `${fmtDate(m.next_run)} <small class="muted">${fmtTime(m.next_run)}</small>`);
    return `<tr>
      <td><strong>${esc(m.target)}</strong>${m.last_file ? `<div><a class="linkbtn" style="padding:0" href="#/scan/${encodeURIComponent(m.last_file)}">latest scan →</a></div>` : ""}${m.last_error ? `<div class="muted wrap" style="font-size:11px">${esc(m.last_error)}</div>` : ""}</td>
      <td>${esc(m.every)}</td>
      <td>${st} ${m.enabled ? "" : '<span class="tag lc-hist">paused</span>'}</td>
      <td class="when">${last}</td>
      <td>${next}</td>
      <td class="num">${m.last_alerts || 0}</td>
      <td>${m.webhook_kind ? `${esc(m.webhook_kind)} <small class="muted">≥ ${esc(m.min_severity)}</small>` : '<span class="muted">—</span>'}</td>
      <td><div class="rowacts">
        <button class="ghost sm" onclick="monAction('${m.id}','run',this)" ${m.last_status === "running" ? "disabled" : ""}>Run now</button>
        <button class="ghost sm" onclick="monAction('${m.id}','${m.enabled ? "pause" : "resume"}',this)">${m.enabled ? "Pause" : "Resume"}</button>
        ${m.webhook_kind ? `<button class="ghost sm" onclick="monAction('${m.id}','test',this)">Test webhook</button>` : ""}
        <button class="ghost sm danger" onclick="monAction('${m.id}','delete',this)">Remove</button></div></td></tr>`;
  }).join("");
  const sel = document.getElementById("alertTarget"), cur = sel.value;
  sel.innerHTML = `<option value="">All targets</option>` + [...new Set(MON.alerts.map(a => a.target))].sort().map(t => `<option ${t === cur ? "selected" : ""}>${esc(t)}</option>`).join("");
}

async function monAction(id, action, btn) {
  if (action === "delete" && !confirmInline(btn, "Remove?")) return;
  btn.disabled = true;
  try {
    await api(`/api/monitors/${id}/${action}`);
    toast({ run: "Scan started — results appear here in a few minutes", pause: "Monitor paused", resume: "Monitor resumed", delete: "Monitor removed (its saved scans and alerts are kept)", test: "Test alert delivered" }[action]);
  } catch (e) { toast(e.message); }
  await loadMonitoring(true);
}

/* Two-click confirmation without a browser dialog. */
function confirmInline(btn, label) {
  if (btn.dataset.armed) return true;
  const old = btn.textContent; btn.dataset.armed = "1"; btn.textContent = label;
  setTimeout(() => { delete btn.dataset.armed; btn.textContent = old; }, 3000);
  return false;
}

async function addMonitor(ev) {
  ev.preventDefault();
  const err = document.getElementById("monErr"); err.classList.add("hidden");
  const rules = [...document.querySelectorAll("#monRules input:checked")].map(i => i.value);
  const body = {
    target: document.getElementById("monTarget").value.trim(),
    every: document.getElementById("monEvery").value,
    webhook: document.getElementById("monHook").value.trim(),
    min_severity: document.getElementById("monSev").value,
    archive_raw: document.getElementById("monArchive").checked,
    rules: rules.length === MON.rules.length ? [] : rules,
  };
  if (!body.target) { err.textContent = "Enter a domain, e.g. example.com."; err.classList.remove("hidden"); return; }
  if (!rules.length) { err.textContent = "Pick at least one alert rule."; err.classList.remove("hidden"); return; }
  const btn = document.getElementById("monAdd"); btn.disabled = true;
  try {
    await api("/api/monitors", body);
    document.getElementById("monTarget").value = ""; document.getElementById("monHook").value = "";
    toast(MON.scheduler ? `Monitoring ${body.target} — the baseline scan starts within a minute` : `Monitoring ${body.target} — baseline scan started`);
    await loadMonitoring(true);
  } catch (e) { err.textContent = e.message; err.classList.remove("hidden"); }
  btn.disabled = false;
}

function renderAlerts() {
  const t = document.getElementById("alertTarget").value;
  const list = MON.alerts.filter(a => !t || a.target === t);
  document.getElementById("alertCount").textContent = `${list.length} alert${list.length === 1 ? "" : "s"}`;
  document.getElementById("alertList").innerHTML = list.length ? list.map(alertHTML).join("")
    : `<div class="muted" style="padding:14px 0">No alerts yet. The first run of a monitor saves a baseline; later runs alert on changes.</div>`;
}

function alertHTML(a) {
  const items = (a.items || []).map(i => `<li>${esc(i)}</li>`).join("") + (a.more ? `<li class="muted">…and ${a.more} more</li>` : "");
  return `<div class="alert"><span class="tag ${SEV_CLS[a.severity] || "sev-info"}">${esc(a.severity)}</span>
    <div style="min-width:0;flex:1"><div><b>${esc(a.title)}</b></div>
      <div class="muted" style="font-size:11.5px">${esc(fmtFull(a.time))} · ${esc(a.rule.replace(/_/g, " "))}${a.delivered ? ` · webhook: ${esc(a.delivered)}` : ""}
        ${a.scan_file ? ` · <a href="#/scan/${encodeURIComponent(a.scan_file)}" style="color:var(--accent)">open scan</a>` : ""}</div>
      ${items ? `<ul class="notes">${items}</ul>` : ""}</div></div>`;
}

/* Dashboard card: latest alerts across monitors. */
async function renderAlertCard(fetchFirst) {
  const card = document.getElementById("alertCard");
  if (!card) return;
  if (fetchFirst) {
    try { MON.alerts = await fetch("/api/alerts?limit=200").then(r => r.json()); } catch (e) { return; }
  }
  const notable = MON.alerts.filter(a => a.severity !== "info").slice(0, 5);
  card.classList.toggle("hidden", !MON.alerts.length);
  document.getElementById("alertCardBody").innerHTML = notable.length ? notable.map(alertHTML).join("")
    : `<div class="muted">No changes detected by your monitors yet.</div>`;
}

/* ───────── Settings: API keys ───────── */
async function showSettings() {
  const box = document.getElementById("keyRows");
  let data;
  try { data = await fetch("/api/keys").then(r => r.json()); } catch (e) { box.innerHTML = `<tr><td colspan="4" class="errbox">Could not load keys.</td></tr>`; return; }
  document.getElementById("keyFile").textContent = data.file;
  box.innerHTML = (data.keys || []).map(k => {
    const src = { env: `<span class="tag t-both" title="Set in the environment of the reconx process">environment</span>`, file: `<span class="tag t-passive">stored</span>`, unset: `<span class="tag lc-hist">not set</span>` }[k.source];
    return `<tr data-k="${esc(k.name)}">
      <td><b>${esc(k.service)}</b><div class="muted" style="font-size:11.5px">${esc(k.effect)}</div><div style="font-size:11px"><code>${esc(k.env)}</code> · <a href="${esc(k.get_url)}" target="_blank" rel="noopener" style="color:var(--accent)">get a key ↗</a></div></td>
      <td>${src}${k.hint ? ` <code>${esc(k.hint)}</code>` : ""}${k.shadowed ? `<div class="muted" style="font-size:11px">overrides the stored key</div>` : ""}</td>
      <td><div class="keyset"><input type="password" class="filter" placeholder="${k.source === "unset" ? "Paste key" : "Replace key"}" autocomplete="off" spellcheck="false">
        <button class="ghost sm" onclick="saveKey(this)">Save</button></div><div class="keymsg muted" style="font-size:11.5px;margin-top:4px"></div></td>
      <td><div class="rowacts"><button class="ghost sm" onclick="testKey(this)" ${k.source === "unset" ? "disabled" : ""}>Test</button>
        ${k.source === "file" ? `<button class="ghost sm danger" onclick="removeKey(this)">Remove</button>` : ""}</div></td></tr>`;
  }).join("");
}

function keyRow(btn) { return btn.closest("tr[data-k]"); }

async function saveKey(btn) {
  const row = keyRow(btn), input = row.querySelector("input"), msg = row.querySelector(".keymsg");
  const value = input.value.trim();
  if (!value) { msg.textContent = "Paste a key first."; return; }
  btn.disabled = true;
  try {
    await api("/api/keys", { name: row.dataset.k, value });
    input.value = "";
    const t = await api("/api/keys/test", { name: row.dataset.k });
    toast(t.ok ? "Key saved and verified" : "Key saved — but the check failed: " + t.detail);
    await showSettings();
    const again = document.querySelector(`tr[data-k="${row.dataset.k}"] .keymsg`);
    if (again) again.textContent = (t.ok ? "✓ " : "✕ ") + t.detail;
  } catch (e) { msg.textContent = e.message; btn.disabled = false; }
}

async function testKey(btn) {
  const row = keyRow(btn), msg = row.querySelector(".keymsg");
  btn.disabled = true; msg.textContent = "Checking…";
  try { const t = await api("/api/keys/test", { name: row.dataset.k }); msg.textContent = (t.ok ? "✓ " : "✕ ") + t.detail; }
  catch (e) { msg.textContent = e.message; }
  btn.disabled = false;
}

async function removeKey(btn) {
  if (!confirmInline(btn, "Remove?")) return;
  try { await api("/api/keys", { name: keyRow(btn).dataset.k, value: "" }); toast("Key removed"); } catch (e) { toast(e.message); }
  showSettings();
}
