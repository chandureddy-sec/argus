/* ReconX scan detail view — tabbed passive-intelligence report.
 * Uses helpers defined in index.html: esc, fmtFull, date, sevRank, sevCls,
 * downloadMenu, reportURLs, modeOf, SCANS, saveFromDetail.
 */
let DETAIL = null; // {rep, kind, id, tab, filter, role, q, sort, dir}

const TABS = [
  ["overview", "Overview"], ["subdomains", "Subdomains"], ["dns", "DNS"], ["email", "Email Security"],
  ["certs", "Certificates"], ["infra", "Infrastructure"], ["graph", "Graph"], ["map", "Map"], ["changes", "Changes"], ["sources", "Sources"], ["threat", "Threat Intel"], ["active", "Active Metadata"],
];

function renderDetail(rep, kind, id) {
  const prevTab = DETAIL && DETAIL.id === id ? DETAIL.tab : "overview";
  DETAIL = { rep, kind, id, tab: prevTab, filter: "all", role: "", q: "", sort: "interest_score", dir: -1, open: {} };
  const d = document.getElementById("detail");
  const u = reportURLs(kind, id);
  const pi = rep.passive_intel;
  const mode = modeOf(rep), target = rep.target?.value || "scan";
  document.getElementById("pageSub").textContent = target;

  const tabs = TABS.filter(([k]) => tabAvailable(k, rep));
  if (!tabs.find(([k]) => k === DETAIL.tab)) DETAIL.tab = tabs[0]?.[0] || "overview";

  d.innerHTML = `<div class="dhead"><div>
      <h2>${esc(target)}</h2>
      <div class="muted" style="margin-top:4px">${esc(fmtFull(rep.timestamp))} · <span class="tag t-${mode}">${mode}</span>
        ${pi ? '<span class="tag t-passive" title="Passive Scan data comes only from public third-party sources and public DNS">passive-only sources</span>' : ""}
        ${kind === "job" ? ' <span class="tag t-unsaved">unsaved</span>' : ""}</div>
    </div>
    <div class="acts" style="margin-top:0">${downloadMenu(u, true)}
      ${kind === "job" ? `<button class="ghost" onclick="saveFromDetail('${esc(id)}',this)">Save to history</button>` : ""}
      <a class="ghost" href="${u.html}" target="_blank" rel="noopener">Open full report ↗</a></div></div>
    ${pi ? "" : `<div class="notice">This scan predates the passive-intelligence model. Run a new scan of <b>${esc(target)}</b> for certificates, email security, history and change tracking.</div>`}
    <div class="tabs" role="tablist">${tabs.map(([k, l]) => `<button role="tab" data-tab="${k}" class="${k === DETAIL.tab ? "on" : ""}">${l}${tabBadge(k, rep)}</button>`).join("")}</div>
    <div id="tabBody"></div>`;
  d.querySelectorAll(".tabs button").forEach(b => b.onclick = () => { DETAIL.tab = b.dataset.tab; d.querySelectorAll(".tabs button").forEach(x => x.classList.toggle("on", x === b)); renderTab(); });
  renderTab();
}

function tabAvailable(k, rep) {
  const pi = rep.passive_intel;
  switch (k) {
    case "overview": return true;
    case "subdomains": return !!(pi?.hosts?.length || rep.attack_surface_graph?.nodes?.length || rep.normalized_assets?.length);
    case "dns": return !!(rep.dns || pi);
    case "email": case "certs": case "infra": case "sources": case "graph": case "map": return !!pi;
    case "changes": return !!(pi || rep.normalized_assets);
    case "active": return !!(rep.active_recon || rep.web_map);
    case "threat": return !!rep.threat_intel;
  }
  return false;
}
function tabBadge(k, rep) {
  if (k === "threat" && rep.threat_intel) { const c = rep.threat_intel.counts || {}; const n = (c.malicious || 0) + (c.suspicious || 0); return n ? ` <span class="cnt hot">${n}</span>` : ""; }
  const pi = rep.passive_intel; if (!pi) return "";
  if (k === "subdomains") return ` <span class="cnt">${pi.hosts?.length || 0}</span>`;
  if (k === "certs") return ` <span class="cnt">${pi.certificate_summary?.total || 0}</span>`;
  if (k === "changes" && pi.changes) { const s = pi.changes.summary; const n = s.subdomains_added + s.subdomains_removed + s.hosts_changed + s.dns_changes + s.provider_changes; return n ? ` <span class="cnt hot">${n}</span>` : ""; }
  if (k === "sources") { const bad = (pi.sources || []).filter(s => s.status !== "success").length; return bad ? ` <span class="cnt warn">${bad}</span>` : ""; }
  return "";
}

function renderTab() {
  const b = document.getElementById("tabBody");
  const r = DETAIL.rep;
  const fn = { overview: tabOverview, subdomains: tabSubdomains, dns: tabDNS, email: tabEmail, certs: tabCerts, infra: tabInfra, graph: tabGraph, map: tabMap, changes: tabChanges, sources: tabSources, threat: tabThreat, active: tabActive }[DETAIL.tab];
  if (GRAPH?.raf) cancelAnimationFrame(GRAPH.raf);
  b.innerHTML = fn ? fn(r) : "";
  if (DETAIL.tab === "subdomains") wireSubdomains();
  if (DETAIL.tab === "changes") wireChanges();
  if (DETAIL.tab === "certs") wireCerts();
  if (DETAIL.tab === "graph") wireGraph();
  if (DETAIL.tab === "map") wireMap();
}

/* ───────── shared bits ───────── */
const EV = {
  observed: '<span class="ev ev-o" title="Observed: returned directly by a source">observed</span>',
  enriched: '<span class="ev ev-e" title="Enriched: joined with another public source">enriched</span>',
  inferred: '<span class="ev ev-i" title="Inferred: a classification or prediction — requires verification">inferred</span>',
};
function d10(s) { return s ? String(s).slice(0, 10) : "—"; }
function pill(text, cls) { return `<span class="tag ${cls}">${esc(text)}</span>`; }
function lifeTag(l) { return pill(l || "—", { new: "lc-new", changed: "lc-changed", active: "lc-active", historical: "lc-hist", removed: "lc-removed" }[l] || "lc-hist"); }
function confTag(level, n) { return `<span class="tag conf-${level}" title="Confidence ${n}/100">${level} · ${n}</span>`; }
function interestTag(l) { return pill(l, "int-" + l); }
function card(title, body, extra) { return `<div class="ic ${extra || ""}"><div class="ic-h">${title}</div>${body}</div>`; }
function stat(v, k) { return `<div class="mini"><b>${v}</b><span>${k}</span></div>`; }
function kvTable(rows) {
  const r = rows.filter(([, v]) => v !== undefined && v !== null && v !== "");
  return r.length ? `<div class="tbl"><table><tbody>${r.map(([k, v, raw]) => `<tr><td class="muted" style="width:170px">${k}</td><td>${raw ? v : esc(v)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="muted">No data.</div>`;
}
function check(ok, label, detail) {
  return `<div class="chk ${ok === true ? "ok" : ok === false ? "no" : "na"}"><span>${ok === true ? "✓" : ok === false ? "✕" : "?"}</span><div><b>${label}</b><small>${esc(detail || "")}</small></div></div>`;
}

/* ───────── Overview ───────── */
function tabOverview(r) {
  const pi = r.passive_intel, ag = pi?.aggregates || {};
  let h = "";
  // Target overview
  const ns = pi?.nameservers?.map(n => n.hostname).join(", ") || (r.dns?.records || []).filter(x => x.type === "NS").map(x => x.value).join(", ");
  h += `<div class="grid2">` + card("Target overview", kvTable([
    ["Domain", r.target?.value], ["Registrar", r.rdap?.registrar], ["Registrant org", r.rdap?.organization],
    ["Created", date(r.rdap?.created_date)], ["Expires", date(r.rdap?.expiry_date)], ["Nameservers", ns],
    ["DNSSEC", pi?.dnssec?.status],
  ]));
  // Changes
  if (pi?.changes) {
    const s = pi.changes.summary;
    h += card(`Changes since previous scan <small class="muted">(${esc(fmtFull(pi.changes.previous_scan))})</small>`,
      `<div class="minis">${stat(`+${s.subdomains_added} / −${s.subdomains_removed}`, "subdomains")}${stat(s.hosts_changed, "hosts changed")}${stat(`+${s.ips_added} / −${s.ips_removed}`, "IPs")}${stat(s.dns_changes, "apex DNS changes")}${stat(`+${s.certificates_added}`, "new certificates")}${stat(s.certificates_removed, "certs expired")}${stat(s.provider_changes, "provider changes")}${stat(s.unchanged_hosts, "unchanged hosts")}</div>`);
  } else if (pi) {
    h += card("Changes", `<div class="muted">No earlier saved scan of this target to compare against. Save this scan to start tracking changes.</div>`);
  }
  h += `</div>`;
  if (!pi) return h + legacyOverview(r);

  // Attack surface metrics
  h += `<h3>Attack surface</h3><div class="minis wide">${stat(ag.subdomains, "subdomains")}${stat(ag.resolving, "resolving hosts")}${stat(ag.unique_ips, `unique IPs (${ag.ipv4} v4 · ${ag.ipv6} v6)`)}${stat(ag.asns, "ASNs")}${stat(ag.countries, "countries")}${stat(ag.certificates, "certificates")}${stat(ag.historical_hosts, "not resolving now")}${stat(ag.historical_ips, "historical IPs")}${stat(ag.high_interest, "high-interest hosts")}${stat((pi.email_security?.mail_providers || []).length, "mail providers")}</div>`;

  // Security posture
  const es = pi.email_security || {}, cs = pi.certificate_summary || {};
  h += `<h3>Security posture <small class="muted">— posture indicators, not vulnerabilities</small></h3><div class="grid3">`;
  h += card("DNS security", check(pi.dnssec?.enabled, "DNSSEC", pi.dnssec?.status) + check(pi.caa?.present, "CAA", pi.caa?.present ? `${pi.caa.posture}: ${(pi.caa.issue || []).join(", ") || "—"}` : "No CAA (any public CA may issue)"));
  h += card(`Email security <small class="muted">${es.score}/${es.max_score}</small>`,
    check(es.spf?.present ? (es.spf.valid ? true : false) : false, "SPF", es.spf?.present ? (es.spf.all || "") + " " + (es.spf.valid ? "" : "(invalid)") : "missing") +
    check(es.dkim?.found?.length ? true : null, "DKIM", es.dkim?.found?.length ? es.dkim.found.map(k => k.selector).join(", ") : "not found at well-known selectors (inconclusive)") +
    check(es.dmarc?.present && es.dmarc.valid ? true : false, "DMARC", es.dmarc?.present ? "p=" + (es.dmarc.policy || "?") : "missing") +
    check(!!es.mta_sts?.present, "MTA-STS", es.mta_sts?.present ? "published" : "not published") +
    check(!!es.tls_rpt?.present, "TLS-RPT", es.tls_rpt?.present ? "published" : "not published"));
  h += card("Certificate health", `<div class="minis">${stat(cs.valid || 0, "valid")}${stat(cs.expiring_7d || 0, "< 7 days")}${stat(cs.expiring_30d + cs.expiring_14d || 0, "7–30 days")}${stat(cs.expired || 0, "expired")}</div>`);
  h += `</div>`;

  // Infrastructure
  h += `<h3>Infrastructure ${EV.inferred}</h3><div class="grid3">`;
  h += card("Cloud / hosting / CDN", countList(ag.by_cloud, "hosts"));
  h += card("ASNs", (ag.by_asn || []).slice(0, 8).map(a => `<div class="cl"><span>${esc(a.asn)} <small class="muted">${esc(a.name || "")}</small></span><b>${a.hosts}</b></div>`).join("") || `<div class="muted">—</div>`);
  h += card("Countries <small class='muted'>(per ip-api; approximate)</small>", countList(ag.by_country, "IPs"));
  h += `</div>`;
  if (pi.providers?.length) {
    h += `<h3>Third-party & provider map ${EV.inferred}</h3><div class="tbl"><table><thead><tr><th>Category</th><th>Likely provider</th><th class="num">Hosts</th><th>Evidence</th></tr></thead><tbody>` +
      pi.providers.map(p => `<tr><td>${esc(p.category)}</td><td>${esc(p.name)}</td><td class="num">${p.hosts}</td><td class="muted">${esc(p.evidence.join(" · "))}</td></tr>`).join("") + `</tbody></table></div>`;
  }
  if (pi.dangling_dns?.length) {
    h += `<h3>Potential dangling DNS ${EV.inferred}</h3><div class="note2">These CNAMEs point to names that no longer resolve. This is passive detection only — it requires verification and is not a confirmed takeover.</div>` +
      pi.dangling_dns.map(x => `<div class="finding"><span class="tag sev-medium">potential</span><div><div>${esc(x.hostname)} → <code>${esc(x.cname)}</code></div><div class="muted" style="font-size:12px">${esc(x.reason)}</div></div></div>`).join("");
  }
  const top = (pi.hosts || []).filter(x => x.interest === "high").slice(0, 8);
  if (top.length) {
    h += `<h3>Highest investigation priority</h3>` + top.map(x => `<div class="finding"><span class="tag int-high">high</span><div><div><b>${esc(x.hostname)}</b> · ${esc(x.role)}</div><div class="muted" style="font-size:12px">${esc((x.interest_factors || []).join(" · "))}</div></div></div>`).join("");
  }
  return h;
}
function countList(arr, unit) {
  if (!arr?.length) return `<div class="muted">—</div>`;
  return arr.slice(0, 8).map(c => `<div class="cl"><span>${esc(c.name)}</span><b>${c.count} <small class="muted">${unit}</small></b></div>`).join("");
}
function legacyOverview(r) {
  const g = r.attack_surface_graph;
  return `<h3>Attack surface</h3><div class="minis wide">${stat((r.normalized_assets || []).length, "subdomains")}${stat(g?.live_assets || 0, "resolving hosts")}</div>`;
}

/* ───────── Subdomains ───────── */
const FILTERS = [["all", "All"], ["resolves", "Resolving"], ["historical", "Not resolving"], ["new", "New"], ["changed", "Changed"], ["high", "High interest"], ["dangling", "Potential dangling"]];
function hostsOf(r) {
  if (r.passive_intel?.hosts) return r.passive_intel.hosts;
  const nodes = r.attack_surface_graph?.nodes || [];
  if (nodes.length) return nodes.map(n => ({ hostname: n.hostname, sources: n.sources, source_count: (n.sources || []).length, dns_status: n.is_alive ? "resolves" : "no_address", ips: n.resolved_ips, asn: n.asn, organization: n.organization, cloud: n.cloud_provider, confidence: Math.round(n.confidence * 100), confidence_level: n.confidence >= .85 ? "high" : n.confidence >= .6 ? "medium" : "low", role: "", interest: "", lifecycle: "" }));
  return (r.normalized_assets || []).map(a => ({ hostname: a.asset, sources: a.sources, source_count: a.sources.length, confidence: Math.round(a.confidence * 100), confidence_level: "", dns_status: "", role: "", interest: "", lifecycle: "" }));
}
function tabSubdomains(r) {
  const hosts = hostsOf(r);
  const roles = [...new Set(hosts.map(h => h.role).filter(Boolean))].sort();
  return `<div class="toolbar">
      <div class="chips">${FILTERS.map(([k, l]) => `<button class="chip2 ${DETAIL.filter === k ? "on" : ""}" data-f="${k}">${l} <span>${countFilter(hosts, k)}</span></button>`).join("")}</div>
      <div class="tright">
        <select id="roleSel" class="filter"><option value="">All roles</option>${roles.map(x => `<option ${DETAIL.role === x ? "selected" : ""}>${esc(x)}</option>`).join("")}</select>
        <input id="hostQ" class="filter" type="search" placeholder="Search host, IP, ASN…" value="${esc(DETAIL.q)}">
      </div></div>
    <div class="evlegend">${EV.observed} DNS status, IPs, sources ${EV.enriched} ASN, org, country ${EV.inferred} cloud/CDN, likely role, interest</div>
    <div class="tbl scroll"><table class="hosts"><thead><tr>
      ${[["hostname", "Hostname"], ["lifecycle", "Status"], ["confidence", "Confidence"], ["source_count", "Sources"], ["first_seen", "First seen"], ["last_seen", "Last seen"], ["ips", "IPs"], ["asn", "ASN / Org"], ["cloud", "Cloud / CDN"], ["role", "Likely role"], ["certificates", "Certs"], ["interest_score", "Interest"]]
      .map(([k, l]) => `<th data-sort="${k}" class="${DETAIL.sort === k ? "sorted" : ""}">${l}${DETAIL.sort === k ? (DETAIL.dir > 0 ? " ▲" : " ▼") : ""}</th>`).join("")}
    </tr></thead><tbody id="hostRows"></tbody></table></div>
    <div class="muted" id="hostCount" style="margin-top:8px;font-size:12px"></div>`;
}
function countFilter(hosts, k) { return hosts.filter(h => passFilter(h, k)).length; }
function passFilter(h, k) {
  switch (k) {
    case "resolves": return h.dns_status === "resolves";
    case "historical": return h.dns_status && h.dns_status !== "resolves";
    case "new": return h.lifecycle === "new";
    case "changed": return h.lifecycle === "changed";
    case "high": return h.interest === "high";
    case "dangling": return (DETAIL.rep.passive_intel?.dangling_dns || []).some(x => x.hostname === h.hostname);
  }
  return true;
}
function wireSubdomains() {
  document.querySelectorAll(".chip2").forEach(b => b.onclick = () => { DETAIL.filter = b.dataset.f; document.querySelectorAll(".chip2").forEach(x => x.classList.toggle("on", x === b)); drawHosts(); });
  document.getElementById("roleSel").onchange = e => { DETAIL.role = e.target.value; drawHosts(); };
  document.getElementById("hostQ").oninput = e => { DETAIL.q = e.target.value.toLowerCase(); drawHosts(); };
  document.querySelectorAll("table.hosts th[data-sort]").forEach(th => th.onclick = () => {
    const k = th.dataset.sort; DETAIL.dir = DETAIL.sort === k ? -DETAIL.dir : (k === "hostname" ? 1 : -1); DETAIL.sort = k; renderTab();
  });
  document.getElementById("hostRows").onclick = e => {
    const tr = e.target.closest("tr[data-h]"); if (!tr) return;
    DETAIL.open[tr.dataset.h] = !DETAIL.open[tr.dataset.h]; drawHosts();
  };
  drawHosts();
}
function drawHosts() {
  const q = DETAIL.q;
  let list = hostsOf(DETAIL.rep).filter(h => passFilter(h, DETAIL.filter) && (!DETAIL.role || h.role === DETAIL.role) &&
    (!q || [h.hostname, (h.ips || []).join(" "), h.asn, h.organization, h.cloud, h.cdn, h.role].join(" ").toLowerCase().includes(q)));
  const k = DETAIL.sort, dir = DETAIL.dir;
  list = list.slice().sort((a, b) => {
    let x = a[k], y = b[k];
    if (k === "ips") { x = (a.ips || []).length; y = (b.ips || []).length; }
    if (k === "cloud") { x = a.cdn || a.cloud || ""; y = b.cdn || b.cloud || ""; }
    if (x === undefined || x === null) x = ""; if (y === undefined || y === null) y = "";
    return (x > y ? 1 : x < y ? -1 : 0) * dir || a.hostname.localeCompare(b.hostname);
  });
  const shown = list.slice(0, 500);
  document.getElementById("hostRows").innerHTML = shown.map(h => hostRow(h) + (DETAIL.open[h.hostname] ? hostDetail(h) : "")).join("") ||
    `<tr><td colspan="12" class="muted">No hosts match.</td></tr>`;
  document.getElementById("hostCount").textContent = `${list.length} host${list.length === 1 ? "" : "s"}${list.length > 500 ? " (first 500 shown — use search or the CSV export)" : ""} · click a row for evidence`;
}
function hostRow(h) {
  const dns = h.dns_status === "resolves" ? '<span class="dot ok" title="Resolves now"></span>' : h.dns_status ? `<span class="dot no" title="${esc(h.dns_status)}"></span>` : "";
  return `<tr data-h="${esc(h.hostname)}" class="${DETAIL.open[h.hostname] ? "open" : ""}">
    <td><b>${esc(h.hostname)}</b>${(h.indicators || []).length ? ` <small class="ind">${esc(h.indicators.join(" · "))}</small>` : ""}${h.web?.title ? `<div class="muted" style="font-size:11px" title="urlscan.io capture">“${esc(h.web.title)}”</div>` : ""}</td>
    <td>${dns}${h.lifecycle ? lifeTag(h.lifecycle) : ""}</td>
    <td>${h.confidence_level ? confTag(h.confidence_level, h.confidence) : (h.confidence ?? "")}</td>
    <td title="${esc((h.sources || []).join(", "))}">${h.source_count || 0} <small class="muted">${esc((h.sources || []).slice(0, 3).join(", "))}</small></td>
    <td class="muted">${d10(h.first_seen)}</td><td class="muted">${d10(h.last_seen)}</td>
    <td>${esc((h.ips || []).slice(0, 2).join(", "))}${(h.ips || []).length > 2 ? ` <small class="muted">+${h.ips.length - 2}</small>` : ""}</td>
    <td>${esc(h.asn ? h.asn.split(" ")[0] : "")} <small class="muted">${esc(h.organization || "")}</small></td>
    <td>${esc(h.cdn || h.cloud || "")}</td>
    <td>${esc(h.role || "")}</td>
    <td class="num">${h.certificates ?? ""}</td>
    <td>${h.interest ? interestTag(h.interest) : ""}</td></tr>`;
}
function hostDetail(h) {
  const ev = (h.evidence || []).map(e => `<tr><td>${esc(e.source)}</td><td>${pill(e.reliability, "rel-" + e.reliability)}</td><td>${d10(e.first_seen)}</td><td>${d10(e.last_seen)}</td></tr>`).join("");
  const hist = (h.history || []).slice().sort((a, b) => (b.current - a.current) || String(b.last_seen).localeCompare(String(a.last_seen)))
    .map(v => `<tr><td>${esc(v.type)}</td><td><code>${esc(v.value)}</code></td><td>${v.current ? pill("current", "lc-active") : pill("historical", "lc-hist")}</td><td>${d10(v.first_seen)}</td><td>${d10(v.last_seen)}</td><td class="muted">${esc(v.source)}</td></tr>`).join("");
  return `<tr class="xrow"><td colspan="12"><div class="xgrid">
    <div><h4>Source evidence ${EV.observed}</h4><div class="tbl"><table><thead><tr><th>Source</th><th>Reliability</th><th>First seen</th><th>Last seen</th></tr></thead><tbody>${ev || '<tr><td colspan="4" class="muted">—</td></tr>'}</tbody></table></div>
      <div class="muted" style="font-size:12px;margin-top:6px">Confidence ${h.confidence}/100 (${h.confidence_level}) · Recency: <b>${esc(h.recency || "—")}</b> · DNS: ${esc(h.dns_status || "—")}${(h.cnames || []).length ? " · CNAME → " + esc(h.cnames.join(" → ")) : ""}</div></div>
    <div><h4>DNS values — current & historical</h4><div class="tbl"><table><thead><tr><th>Type</th><th>Value</th><th>Status</th><th>First</th><th>Last</th><th>Source</th></tr></thead><tbody>${hist || '<tr><td colspan="6" class="muted">No DNS values observed.</td></tr>'}</tbody></table></div>
      ${h.interest_factors?.length ? `<h4 style="margin-top:12px">Interest factors ${EV.inferred}</h4><div class="muted" style="font-size:12px">${esc(h.interest_factors.join(" · "))}</div>` : ""}
      ${h.cloud || h.cdn ? `<div class="muted" style="font-size:12px;margin-top:8px">${EV.inferred} ${esc([h.cdn, h.cloud].filter(Boolean).join(" · "))} — from CNAME / ASN evidence</div>` : ""}
      ${webCapture(h.web)}
      ${h.code_refs?.length ? `<h4 style="margin-top:12px">Mentioned in public code ${EV.observed} <small class="muted">GitHub</small></h4><div style="font-size:12px">${h.code_refs.map(u => `<div><a href="${esc(u)}" target="_blank" rel="noopener" style="color:var(--accent)">${esc(u.replace("https://github.com/", ""))} ↗</a></div>`).join("")}</div>` : ""}</div>
  </div></td></tr>`;
}
/* Newest urlscan.io capture of the host: what it served when a third party scanned it. */
function webCapture(w) {
  if (!w) return "";
  const link = (u, t) => u ? `<a href="${esc(u)}" target="_blank" rel="noopener" style="color:var(--accent)">${t} ↗</a>` : "";
  return `<h4 style="margin-top:12px">Archived page capture ${EV.observed} <small class="muted">urlscan.io · ${d10(w.captured_at)}${w.scans > 1 ? ` · ${w.scans} scans` : ""}</small></h4>` +
    kvTable([["Title", w.title || "—"], ["URL", w.url], ["HTTP status", w.http_status], ["Server", w.server], ["IP / ASN", [w.ip, w.asn].filter(Boolean).join(" · ")], ["TLS issuer", w.tls_issuer], ["Technologies", (w.technologies || []).join(", ")]].filter(r => r[1])) +
    `<div style="font-size:12px;margin-top:6px">${[link(w.scan_url, "urlscan result"), link(w.screenshot, "screenshot")].filter(Boolean).join(" · ")}</div>`;
}

/* ───────── DNS ───────── */
function tabDNS(r) {
  const pi = r.passive_intel, recs = r.dns?.records || [];
  let h = `<h3>Raw DNS records ${EV.observed} <small class="muted">— via public resolvers</small></h3>`;
  h += recs.length ? `<div class="tbl"><table><thead><tr><th>Name</th><th>Type</th><th>Value</th><th class="num">TTL</th></tr></thead><tbody>` +
    recs.map(x => `<tr><td>${esc(x.name)}</td><td>${pill(x.type, "t-passive")}</td><td class="wrap"><code>${esc(x.value)}</code></td><td class="num">${x.ttl}</td></tr>`).join("") + `</tbody></table></div>` : `<div class="muted">No records.</div>`;
  if (!pi) return h;
  const ds = pi.dnssec || {};
  h += `<div class="grid2"><div>` + `<h3>DNSSEC</h3>` + kvTable([
    ["Status", ds.status], ["DS in parent", ds.enabled ? "Yes" : "No"], ["Zone signed (RRSIG)", ds.signed ? "Yes" : "No"],
    ["Validated (AD flag)", ds.validated ? "Yes" : "No"], ["Algorithms", (ds.algorithms || []).join(", ")],
    ["DS records", (ds.ds || []).map(x => `key tag ${x.key_tag} · ${x.algorithm} · ${x.digest_type}`).join("<br>"), true],
    ["DNSKEYs", (ds.dnskeys || []).map(x => `${x.role} · key tag ${x.key_tag} · ${x.algorithm}`).join("<br>"), true],
    ["Error", ds.error],
  ]) + `</div><div><h3>CAA policy</h3>` + caaView(pi.caa) + `</div></div>`;
  if (pi.nameservers?.length) h += `<h3>Authoritative nameservers</h3>` + serverTable(pi.nameservers, false);
  return h;
}
function caaView(c) {
  if (!c) return `<div class="muted">—</div>`;
  return kvTable([["Present", c.present ? "Yes" : "No"], ["Posture", c.posture], ["issue", (c.issue || []).join(", ")], ["issuewild", (c.issuewild || []).join(", ")], ["iodef", (c.iodef || []).join(", ")],
    ["Records", (c.records || []).map(x => `<code>${esc(x.flag)} ${esc(x.tag)} "${esc(x.value)}"</code>`).join(" "), true]]) +
    `<ul class="notes">${(c.notes || []).map(n => `<li>${esc(n)}</li>`).join("")}</ul>`;
}
function serverTable(list, mx) {
  return `<div class="tbl"><table><thead><tr><th>Host</th>${mx ? "<th>Priority</th>" : ""}<th>IPs</th><th>ASN / Org</th><th>Country</th><th>Likely provider ${EV.inferred}</th></tr></thead><tbody>` +
    list.map(s => `<tr><td>${esc(s.hostname)}</td>${mx ? `<td>${s.priority}</td>` : ""}<td>${esc((s.ips || []).join(", ") || "—")}</td><td>${esc(s.asn || "")} <small class="muted">${esc(s.organization || "")}</small></td><td>${esc(s.country || "")}</td><td>${esc(s.provider || "—")}</td></tr>`).join("") + `</tbody></table></div>`;
}

/* ───────── Email ───────── */
function tabEmail(r) {
  const es = r.passive_intel.email_security || {};
  const spf = es.spf || {}, dm = es.dmarc || {}, dk = es.dkim || {}, sts = es.mta_sts || {}, rpt = es.tls_rpt || {};
  let h = `<div class="grid2"><div>${card(`Posture score <span class="score">${es.score}<small>/${es.max_score}</small></span>`,
    `<div class="tbl"><table><thead><tr><th>Control</th><th class="num">Points</th><th>Why</th></tr></thead><tbody>${(es.score_breakdown || []).map(i => `<tr><td>${esc(i.control)}</td><td class="num">${i.points}/${i.max}</td><td class="muted">${esc(i.reason)}</td></tr>`).join("")}</tbody></table></div>
    <div class="muted" style="font-size:12px;margin-top:8px">Method: fixed points per control (SPF 25, DMARC 30, DKIM 20, MTA-STS 15, TLS-RPT 10). DKIM is left out of the maximum when no key is found, because custom selectors can't be discovered passively.</div>`)}</div>
    <div>${card(`Mail infrastructure ${EV.inferred}`, `<div class="muted" style="margin-bottom:8px">Likely providers: <b>${esc((es.mail_providers || []).join(", ") || "—")}</b></div>` + (r.passive_intel.mail_servers?.length ? serverTable(r.passive_intel.mail_servers, true) : `<div class="muted">No MX records.</div>`))}</div></div>`;

  h += `<h3>SPF ${spf.present ? pill(spf.valid ? "valid" : "invalid", spf.valid ? "lc-active" : "lc-removed") : pill("missing", "lc-removed")}</h3>`;
  if (spf.present) {
    h += kvTable([["Raw record", `<code class="wrap">${esc(spf.raw)}</code>`, true], ["Policy", spf.policy], ["DNS lookups", `${spf.lookup_count} of 10 allowed`], ["Senders (inferred)", (spf.senders || []).join(", ")], ["Redirect", spf.redirect]]);
    h += `<div class="tree"><div>${esc(r.target.value)} SPF</div>${(spf.mechanisms || []).map(m => `<div class="leaf">${esc(m.qualifier === "+" ? "" : m.qualifier)}${esc(m.type)}${m.value ? ":" + esc(m.value) : ""}</div>`).join("")}</div>`;
    h += issues(spf.issues);
  }
  h += `<h3>DMARC ${dm.present ? pill(dm.valid ? "p=" + dm.policy : "invalid", dm.policy === "reject" ? "lc-active" : dm.policy === "quarantine" ? "lc-changed" : "lc-hist") : pill("missing", "lc-removed")}</h3>`;
  h += dm.present ? kvTable([["Raw record", `<code class="wrap">${esc(dm.raw)}</code>`, true], ["Posture", dm.posture], ["Policy (p)", dm.policy], ["Subdomain policy (sp)", dm.subdomain_policy], ["Percentage (pct)", dm.pct + "%"],
    ["Aggregate reports (rua)", (dm.rua || []).join(", ")], ["Forensic reports (ruf)", (dm.ruf || []).join(", ")], ["DKIM alignment", dm.adkim], ["SPF alignment", dm.aspf], ["fo / ri", `${dm.fo} / ${dm.ri}s`]]) + issues(dm.issues)
    : `<div class="muted">${esc(dm.posture || "No DMARC record at _dmarc." + r.target.value)}</div>`;
  h += `<h3>DKIM</h3>`;
  h += dk.found?.length ? `<div class="tbl"><table><thead><tr><th>Selector</th><th>Key</th><th>Bits</th><th>Likely service</th><th>Status</th></tr></thead><tbody>${dk.found.map(k => `<tr><td><code>${esc(k.selector)}._domainkey</code></td><td>${esc(k.key_type)}</td><td>${k.key_bits || "—"}</td><td>${esc(k.service || "—")}</td><td>${k.revoked ? pill("revoked", "lc-removed") : pill("active", "lc-active")}</td></tr>`).join("")}</tbody></table></div>`
    : `<div class="muted">No key found at ${dk.selectors_checked?.length || 0} well-known selectors (${esc((dk.selectors_checked || []).join(", "))}). DKIM may still be configured under other selector names — this is inconclusive.</div>`;
  h += `<h3>MTA-STS & TLS-RPT</h3>` + kvTable([["MTA-STS", sts.present ? `Published · id=${esc(sts.id || "")}` : "Not published", true], ["MTA-STS record", sts.raw], ["Note", sts.note],
    ["TLS-RPT", rpt.present ? "Published" : "Not published"], ["TLS-RPT reports to", (rpt.rua || []).join(", ")]]);
  return h;
}
function issues(list) { return list?.length ? `<ul class="notes warnl">${list.map(i => `<li>${esc(i)}</li>`).join("")}</ul>` : ""; }

/* ───────── Certificates ───────── */
function tabCerts(r) {
  const pi = r.passive_intel, s = pi.certificate_summary || {}, certs = pi.certificates || [];
  let h = `<div class="minis wide">${stat(s.total, "certificates in CT")}${stat(s.valid, "currently valid")}${stat(s.expiring_7d, "expire < 7 days")}${stat(s.expiring_14d, "expire 7–14 days")}${stat(s.expiring_30d, "expire 14–30 days")}${stat(s.expired, "expired")}${stat(s.wildcard, "wildcard")}${stat(s.oldest_seen || "—", "oldest issued")}</div>`;
  if (s.issuers?.length) h += `<div class="muted" style="margin:10px 0">Issuers: ${s.issuers.map(i => `${esc(i.name)} (${i.count})`).join(" · ")}</div>`;
  if (s.total > s.listed) h += `<div class="note2">Showing the ${s.listed} most recent of ${s.total} certificates; the summary counts all of them.</div>`;
  h += `<div class="toolbar"><div class="chips">${[["all", "All"], ["valid", "Valid"], ["soon", "Expiring < 30d"], ["expired", "Expired"], ["wild", "Wildcard"], ["ind", "Interesting names"]].map(([k, l]) => `<button class="chip2 cf ${(DETAIL.cf || "all") === k ? "on" : ""}" data-c="${k}">${l}</button>`).join("")}</div></div>`;
  h += `<div class="tbl scroll"><table class="certs"><thead><tr><th>Common name</th><th>Issuer</th><th class="num">SANs</th><th>Wildcard</th><th>Not before</th><th>Not after</th><th>Expiry</th><th>Indicators</th><th>crt.sh</th></tr></thead><tbody id="certRows"></tbody></table></div>`;
  return h;
}
function wireCerts() {
  document.querySelectorAll(".chip2.cf").forEach(b => b.onclick = () => { DETAIL.cf = b.dataset.c; document.querySelectorAll(".chip2.cf").forEach(x => x.classList.toggle("on", x === b)); drawCerts(); });
  document.getElementById("certRows").onclick = e => { const tr = e.target.closest("tr[data-c]"); if (!tr || e.target.closest("a")) return; DETAIL.open["c" + tr.dataset.c] = !DETAIL.open["c" + tr.dataset.c]; drawCerts(); };
  drawCerts();
}
function drawCerts() {
  const f = DETAIL.cf || "all";
  const list = (DETAIL.rep.passive_intel.certificates || []).filter(c => f === "all" || (f === "valid" && c.expiry_status !== "expired") || (f === "soon" && ["lt7", "lt14", "lt30"].includes(c.expiry_status)) || (f === "expired" && c.expiry_status === "expired") || (f === "wild" && c.wildcard) || (f === "ind" && c.indicators?.length));
  const lbl = { expired: ["expired", "lc-removed"], lt7: ["< 7 days", "lc-removed"], lt14: ["< 14 days", "lc-changed"], lt30: ["< 30 days", "lc-changed"], ok: ["> 30 days", "lc-active"] };
  document.getElementById("certRows").innerHTML = list.map(c => {
    const [t, cls] = lbl[c.expiry_status] || ["?", "lc-hist"];
    const row = `<tr data-c="${c.id}" style="cursor:pointer"><td><b>${esc(c.common_name || c.sans?.[0] || "")}</b></td><td>${esc(c.issuer)}</td><td class="num">${c.sans?.length || 0}</td><td>${c.wildcard ? "yes" : ""}</td><td class="muted">${d10(c.not_before)}</td><td class="muted">${d10(c.not_after)}</td><td>${pill(t, cls)}</td><td>${(c.indicators || []).map(i => `<small class="ind">${esc(i)}</small>`).join(" ")}</td><td><a href="https://crt.sh/?id=${c.id}" target="_blank" rel="noopener" style="color:var(--accent)">#${c.id} ↗</a></td></tr>`;
    const open = DETAIL.open["c" + c.id] ? `<tr class="xrow"><td colspan="9"><div class="tree"><div>Certificate #${c.id} · serial <code>${esc(c.serial || "—")}</code> · valid ${c.validity_days} days · logged ${d10(c.logged_at)}</div>${(c.sans || []).map(s => `<div class="leaf">${esc(s)}</div>`).join("")}</div></td></tr>` : "";
    return row + open;
  }).join("") || `<tr><td colspan="9" class="muted">No certificates match.</td></tr>`;
}

/* RIPEstat vs Team Cymru: agreement pill; conflicts and upstreams in the tooltip / below. */
function routingCell(rc) {
  if (!rc) return `<span class="muted">—</span>`;
  const tip = [rc.holder, rc.prefix, rc.rir, rc.upstreams?.length ? "upstreams: " + rc.upstreams.join(", ") : ""].filter(Boolean).join(" · ");
  if (rc.agreement === "disagree") return `<span title="${esc(tip)}">${pill("disagree", "lc-changed")}</span><div class="muted" style="font-size:11px">${esc(rc.conflicts.join("; "))}</div>`;
  return `<span title="${esc(tip)}">${rc.agreement === "agree" ? pill("agrees", "lc-active") : pill("RIPEstat only", "lc-hist")}</span>`;
}

/* Shodan InternetDB exposure, one row per indexed IP. */
function exposureTable(pi) {
  const ag = pi.aggregates || {}, rows = (pi.ips || []).filter(ip => ip.exposure);
  if (!rows.length) return "";
  return `<h3>Exposure — Shodan InternetDB ${EV.observed}</h3><div class="evlegend">${ag.exposed_ips} of ${ag.unique_ips} IPs indexed · ${ag.open_ports} open ports · ${ag.reported_cves || 0} distinct CVE IDs, ${ag.kev_cves || 0} in CISA KEV (KEV first, then by EPSS — Shodan CVEDB). Shodan's last crawl, not a live check; CVE IDs are version-based, unverified indicators.</div>` +
    `<div class="tbl scroll"><table><thead><tr><th>IP</th><th>Hostnames</th><th>Open ports</th><th>CPEs</th><th>Tags</th><th>Reported CVEs</th></tr></thead><tbody>` +
    rows.map(ip => { const e = ip.exposure; return `<tr><td><code>${esc(ip.ip)}</code></td><td class="wrap">${esc((ip.hostnames || []).join(", "))}</td><td>${esc((e.ports || []).join(", "))}</td><td class="wrap muted">${esc((e.cpes || []).join(", "))}</td><td>${(e.tags || []).map(t => `<small class="ind">${esc(t)}</small>`).join(" ")}</td><td class="wrap">${cveCell(e.vulns || [])}</td></tr>`; }).join("") +
    `</tbody></table></div>`;
}

/* CVE chips: KEV in red, EPSS ≥ 0.10 in orange; the rest collapse into "+N more". */
function cveCell(vulns) {
  const chip = v => {
    const cls = v.kev ? "sev-high" : v.epss >= 0.1 ? "sev-medium" : "sev-info";
    const tip = [v.kev ? "CISA KEV" : "", v.ransomware === "Known" ? "used in ransomware" : "", v.enriched ? `EPSS ${v.epss.toFixed(2)} (pct ${(v.epss_percentile * 100).toFixed(0)})` : "not in CVEDB", v.cvss ? `CVSS ${v.cvss}` : "", v.summary || ""].filter(Boolean).join(" · ");
    return `<a class="tag ${cls}" style="text-decoration:none;margin:1px;padding:2px 7px;font-size:10.5px" title="${esc(tip)}" href="https://cvedb.shodan.io/cve/${encodeURIComponent(v.id)}" target="_blank" rel="noopener">${esc(v.id)}${v.kev ? " KEV" : ""}${v.enriched ? ` <small>${v.epss.toFixed(2)}</small>` : ""}</a>`;
  };
  const top = vulns.slice(0, 8).map(chip).join(" ");
  return vulns.length > 8 ? `${top} <small class="muted">+${vulns.length - 8} more</small>` : top;
}

/* ───────── Infrastructure ───────── */
function tabInfra(r) {
  const pi = r.passive_intel, ag = pi.aggregates || {};
  let h = `<h3>ASNs ${EV.enriched}</h3><div class="tbl"><table><thead><tr><th>ASN</th><th>Name</th><th class="num">IPs</th><th class="num">Host links</th><th>Countries</th><th>Likely provider ${EV.inferred}</th></tr></thead><tbody>` +
    (ag.by_asn || []).map(a => `<tr><td>${esc(a.asn)}</td><td>${esc(a.name || "")}</td><td class="num">${a.ips}</td><td class="num">${a.hosts}</td><td>${esc((a.countries || []).join(", "))}</td><td>${esc(a.provider || "—")}</td></tr>`).join("") + `</tbody></table></div>`;
  h += `<h3>IP addresses</h3><div class="evlegend">${EV.observed} IP & hostnames (DNS) ${EV.enriched} ASN, prefix, RIR, geo, reverse DNS ${EV.inferred} provider · Routing check compares RIPEstat with Team Cymru${ag.routing_conflicts ? ` — <b>${ag.routing_conflicts} disagreement${ag.routing_conflicts > 1 ? "s" : ""}</b>` : ""}</div>`;
  h += `<div class="tbl scroll"><table><thead><tr><th>IP</th><th>Ver</th><th>Hostnames</th><th>ASN</th><th>Prefix</th><th>RIR</th><th>Routing check</th><th>Organization / ISP</th><th>Location</th><th>Reverse DNS</th><th>Likely provider</th></tr></thead><tbody>` +
    (pi.ips || []).map(ip => `<tr><td><code>${esc(ip.ip)}</code></td><td>${ip.version === "IPv6" ? "v6" : "v4"}</td><td class="wrap">${esc((ip.hostnames || []).slice(0, 4).join(", "))}${(ip.hostnames || []).length > 4 ? ` <small class="muted">+${ip.hostnames.length - 4}</small>` : ""}</td><td>${esc((ip.asn || "").split(" ")[0])}</td><td>${esc(ip.prefix || "")}</td><td>${esc(ip.rir || "")}</td><td>${routingCell(ip.routing)}</td><td>${esc(ip.organization || "")}${ip.isp && ip.isp !== ip.organization ? ` <small class="muted">${esc(ip.isp)}</small>` : ""}</td><td>${esc([ip.city, ip.region, ip.country].filter(Boolean).join(", "))}</td><td class="wrap muted">${esc(ip.reverse_dns || "")}</td><td>${esc(ip.provider || "")}${ip.hosting ? ' <small class="muted">hosting</small>' : ""}</td></tr>`).join("") + `</tbody></table></div>`;
  h += `<div class="muted" style="font-size:12px;margin-top:8px">Geolocation is as reported by ip-api.com and may be approximate. Reverse DNS is correlation evidence, not proof of ownership.</div>`;
  h += exposureTable(pi);
  if (pi.providers?.length) h += `<h3>Cloud, CDN & third-party providers ${EV.inferred}</h3><div class="tbl"><table><thead><tr><th>Category</th><th>Likely provider</th><th class="num">Hosts</th><th>Evidence</th></tr></thead><tbody>` +
    pi.providers.map(p => `<tr><td>${esc(p.category)}</td><td>${esc(p.name)}</td><td class="num">${p.hosts}</td><td class="muted">${esc(p.evidence.join(" · "))}</td></tr>`).join("") + `</tbody></table></div>`;
  return h;
}

/* ───────── Changes & comparison ───────── */
function tabChanges(r) {
  const pi = r.passive_intel;
  const others = SCANS.filter(s => s.target === (r.target?.value || "").toLowerCase() && s.file && s.file !== DETAIL.id);
  let h = `<div class="toolbar"><div>Compare this scan with
      <select id="cmpSel" class="filter"><option value="">${pi?.changes ? "previous saved scan (default)" : "choose a scan…"}</option>${others.map(s => `<option value="${esc(s.file)}">${esc(fmtFull(s.timestamp))} · ${s.mode}</option>`).join("")}</select></div></div>
    <div id="cmpBody">${pi?.changes ? changeSetView(pi.changes) : `<div class="muted">No earlier saved scan to compare against automatically. Pick one above, or save this scan to start tracking changes.</div>`}</div>`;
  return h;
}
function wireChanges() {
  const sel = document.getElementById("cmpSel"); if (!sel) return;
  sel.onchange = async () => {
    const body = document.getElementById("cmpBody");
    if (!sel.value) { body.innerHTML = DETAIL.rep.passive_intel?.changes ? changeSetView(DETAIL.rep.passive_intel.changes) : ""; return; }
    body.innerHTML = `<div class="muted">Comparing…</div>`;
    const self = DETAIL.kind === "job" ? "job:" + DETAIL.id : DETAIL.id;
    try {
      const res = await fetch(`/api/compare?a=${encodeURIComponent(sel.value)}&b=${encodeURIComponent(self)}`);
      if (!res.ok) throw new Error((await res.text()).trim());
      body.innerHTML = changeSetView(await res.json());
    } catch (e) { body.innerHTML = `<div class="errbox">${esc(e.message || "Comparison failed")}</div>`; }
  };
}
function changeSetView(cs) {
  const s = cs.summary;
  let h = `<div class="muted" style="margin:6px 0 12px">Baseline: ${esc(fmtFull(cs.previous_scan))}${cs.previous_file ? ` · <code>${esc(cs.previous_file)}</code>` : ""}</div>`;
  h += `<div class="minis wide">${stat(`+${s.subdomains_added}`, "new subdomains")}${stat(`−${s.subdomains_removed}`, "removed subdomains")}${stat(`~${s.hosts_changed}`, "hosts changed")}${stat(s.unchanged_hosts, "unchanged")}${stat(`+${s.ips_added} / −${s.ips_removed}`, "IPs")}${stat(s.dns_changes, "apex DNS changes")}${stat(`+${s.certificates_added}`, "new certificates")}${stat(s.certificates_removed, "certs expired")}${stat(s.provider_changes, "provider changes")}</div>`;
  const ev = cs.events || [];
  if (!ev.length) return h + `<div class="muted" style="margin-top:12px">No differences.</div>`;
  const icon = { added: ["+", "lc-new"], removed: ["−", "lc-removed"], changed: ["~", "lc-changed"], expired: ["⌛", "lc-hist"] };
  h += `<div class="tbl" style="margin-top:12px"><table><thead><tr><th></th><th>Category</th><th>Object</th><th>Before</th><th>After</th></tr></thead><tbody>` +
    ev.map(e => { const [ic, cls] = icon[e.action] || ["•", "lc-hist"]; return `<tr><td>${pill(ic + " " + e.action, cls)}</td><td>${esc(e.category)}</td><td><b>${esc(e.key)}</b></td><td class="wrap muted">${esc(e.old || "")}</td><td class="wrap">${esc(e.new || "")}</td></tr>`; }).join("") + `</tbody></table></div>`;
  return h;
}

/* ───────── Sources ───────── */
function tabSources(r) {
  const src = r.passive_intel.sources || [];
  const st = { success: ["success", "lc-active"], timeout: ["timeout", "lc-changed"], error: ["error", "lc-removed"], skipped: ["skipped", "lc-hist"] };
  return `<div class="muted" style="margin-bottom:10px">Every data point keeps its source. A failed source never stops the scan; its results are simply missing. Reliability feeds the confidence model.</div>
    <div class="tbl"><table><thead><tr><th>Source</th><th>Purpose</th><th>Status</th><th class="num">Duration</th><th class="num">Results</th><th>Reliability</th><th>Error / note</th></tr></thead><tbody>` +
    src.map(s => { const [t, cls] = st[s.status] || [s.status, "lc-hist"]; return `<tr><td><b>${esc(s.name)}</b></td><td class="muted">${esc(s.purpose || "")}</td><td>${pill(t, cls)}</td><td class="num">${(s.duration_ms / 1000).toFixed(1)}s</td><td class="num">${s.results}</td><td>${pill(s.reliability, "rel-" + s.reliability)}</td><td class="wrap muted">${esc(s.error || "")}</td></tr>`; }).join("") +
    `</tbody></table></div>` +
    (r.raw_archive ? `<div class="note2">Raw source responses (with a SHA-256 manifest) are archived in <code>${esc(r.raw_archive)}</code>.</div>` : "") +
    `<div class="muted" style="font-size:12px;margin-top:8px">Model version ${r.passive_intel.version} · scanned ${esc(fmtFull(r.timestamp))}</div>`;
}

/* ───────── Threat intel (ThreatLens verdicts) ───────── */
function safeHref(u) { return /^https?:\/\//i.test(u || "") ? u : ""; }
function tabThreat(r) {
  const ti = r.threat_intel, c = ti.counts || {};
  const cls = { malicious: "lc-removed", suspicious: "lc-changed", benign: "lc-active", unknown: "lc-hist" };
  let h = `<div class="muted" style="margin-bottom:10px">${(ti.items || []).length} hosts and IPs checked against <code>${esc(ti.server)}</code> on ${esc(fmtFull(ti.checked_at))} as ${esc(ti.tlp)}:
    <b>${c.malicious || 0}</b> malicious · <b>${c.suspicious || 0}</b> suspicious · ${c.benign || 0} benign · ${c.unknown || 0} unknown.
    Verdicts are ThreatLens's assessment, each with its evidence. An own asset listed as malicious usually means compromise, abuse or a shared IP: verify before acting.</div>`;
  if (ti.error) h += `<div class="notice">ThreatLens ${ti.status === "error" ? "could not be used" : "stopped part-way"}: ${esc(ti.error)}</div>`;
  if (!(ti.items || []).length) return h;
  h += `<div class="tbl"><table><thead><tr><th>Asset</th><th>Verdict</th><th class="num">Score</th><th>Action</th><th>Evidence</th><th>Known to</th></tr></thead><tbody>` +
    ti.items.map(v => {
      const ev = (v.evidence || []).filter(e => e.kind !== "info").map(e => {
        const href = safeHref(e.ref);
        return `<div class="muted" style="font-size:12px"><b>${esc(e.kind)} ${e.weight}</b> · ${esc(e.source)}: ${esc(e.text)}${href ? ` <a href="${esc(href)}" target="_blank" rel="noopener noreferrer">↗</a>` : ""}</div>`;
      }).join("") + (v.related || []).map(x => `<div class="muted" style="font-size:12px">linked to ${esc(x)}</div>`).join("");
      const partial = v.partial ? ` <span class="muted" title="${esc((v.skipped || []).join("; "))}" style="font-size:11px">partial</span>` : "";
      return `<tr><td><b>${esc(v.value)}</b><div class="muted" style="font-size:11px">${esc(v.type)}</div></td><td>${pill(v.verdict, cls[v.verdict] || "lc-hist")}${partial}</td><td class="num">${v.score}</td><td>${esc(v.action)}</td><td class="wrap">${ev || '<span class="muted">—</span>'}</td><td>${esc((v.known_sources || []).join(", ") || "—")}</td></tr>`;
    }).join("") + `</tbody></table></div>`;
  if ((ti.rejected || []).length) h += `<div class="muted" style="font-size:12px;margin-top:8px">Not checked: ${ti.rejected.map(x => esc(x.value) + " (" + esc(x.reason) + ")").join(" · ")}</div>`;
  return h;
}

/* ───────── Active metadata (separate, authorization-gated mode) ───────── */
function tabActive(r) {
  let h = `<div class="notice">Active Metadata comes from direct requests to the target and is only collected in Active or Both mode with authorization. It is kept separate from passive data.</div>`;
  const ar = r.active_recon;
  if (ar) {
    const hp = ar.http_probe;
    if (hp) h += `<h3>HTTP</h3>` + kvTable([["URL", hp.final_url || hp.url], ["Status", hp.status_code], ["Title", hp.title]]);
    if (ar.tls) h += `<h3>TLS handshake</h3>` + kvTable([["Version", ar.tls.tls_version], ["Cipher", ar.tls.cipher_suite], ["Issuer", ar.tls.issuer], ["Expires", date(ar.tls.not_after)]]);
    if (ar.header_analysis?.length) h += headerTable(ar.header_analysis);
    if (ar.tech_stack) h += `<h3>Technology (likely)</h3>` + kvTable([["Server", ar.tech_stack.web_server], ["Language", ar.tech_stack.language], ["CDN", ar.tech_stack.cdn], ["WAF", ar.tech_stack.waf], ["CMS", ar.tech_stack.cms]]);
    if (ar.open_ports?.length) h += `<h3>Open ports</h3><div>` + ar.open_ports.map(p => `<code>${esc(p.port)} ${esc(p.service || "")}</code>`).join(" ") + `</div>`;
    if (ar.nmap) h += nmapView(ar.nmap);
    h += `<h3>Security findings (${(ar.findings || []).length})</h3>` + ((ar.findings || []).length
      ? ar.findings.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity)).map(f => `<div class="finding"><span class="tag ${sevCls(f.severity)}">${esc(f.severity)}</span><div><div>${esc(f.title)}</div><div class="muted" style="font-size:12px">${esc(f.category)}${f.description ? " — " + esc(f.description) : ""}</div></div></div>`).join("")
      : `<div class="muted">No findings.</div>`);
  }
  const wm = r.web_map;
  if (wm) {
    h += `<h3>Web mapping</h3><div class="muted">${wm.total_pages_crawled || 0} pages crawled · ${(wm.forms || []).length} forms · ${(wm.api_endpoints || []).length} API endpoints · ${(wm.js_analysis || []).length} scripts analysed</div>`;
    if (wm.forms?.length) h += `<div class="tbl" style="margin-top:10px"><table><thead><tr><th>Form action</th><th>Method</th><th>Type</th></tr></thead><tbody>` + wm.forms.map(f => `<tr><td>${esc(f.action || "-")}</td><td>${esc(f.method)}</td><td>${f.is_login ? '<span class="tag t-active">login</span>' : f.is_file_upload ? '<span class="tag t-active">upload</span>' : "form"}</td></tr>`).join("") + `</tbody></table></div>`;
    if (wm.api_endpoints?.length) h += `<div class="tbl" style="margin-top:10px"><table><thead><tr><th>API endpoint</th><th>Method</th></tr></thead><tbody>` + wm.api_endpoints.slice(0, 100).map(a => `<tr><td>${esc(a.url || "")}</td><td>${esc(a.method || "")}</td></tr>`).join("") + `</tbody></table></div>`;
    const secrets = (wm.js_analysis || []).filter(j => j.secrets?.length);
    if (secrets.length) h += `<h3>Possible secrets in JavaScript</h3>` + secrets.map(j => `<div class="finding"><span class="tag sev-high">JS</span><div><div>${esc(j.script_url)}</div><div class="muted" style="font-size:12px">${esc(j.secrets.join(", "))}</div></div></div>`).join("");
  }
  return h;
}

/* nmap results (Active Metadata) */
function nmapView(nm) {
  if (!nm.available) return `<h3>Nmap</h3><div class="notice">nmap scan not available: ${esc(nm.unavailable || "unknown")}</div>`;
  const priv = nm.privileged ? "privileged (raw packets)" : "unprivileged connect scan — SYN/OS detection need elevation";
  let h = `<h3>Nmap — ${esc(nm.profile || "")} scan</h3>`;
  h += `<div class="muted" style="font-size:12px;margin-bottom:8px">nmap ${esc(nm.version || "")} · ${esc(nm.scan_type || "?")} scan · ${priv} · ${(nm.elapsed_sec || 0).toFixed(1)}s<br><code>${esc(nm.command || "")}</code></div>`;
  if (nm.host_state && nm.host_state !== "up") h += `<div class="note2">nmap reported host state: ${esc(nm.host_state)}</div>`;
  if (nm.ports?.length) {
    h += `<div class="tbl scroll"><table><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version / Product</th><th>CPE</th></tr></thead><tbody>` +
      nm.ports.map(p => `<tr><td>${p.port}</td><td>${esc(p.protocol)}</td><td>${p.state === "open" ? '<span class="tag lc-active">open</span>' : esc(p.state)}</td><td>${esc(p.service || "")}</td><td>${esc(verStr(p))}</td><td class="wrap"><small class="muted">${esc((p.cpe || []).join(", "))}</small></td></tr>`).join("") + `</tbody></table></div>`;
  }
  if (nm.os_matches?.length) h += `<div style="margin-top:10px"><b>OS detection (best guesses):</b> ${nm.os_matches.slice(0, 3).map(m => `${esc(m.name)} (${m.accuracy}%)`).join(" · ")}</div>`;
  const scripts = [];
  (nm.ports || []).forEach(p => (p.scripts || []).forEach(s => scripts.push([`${p.port}/${p.protocol}`, s])));
  (nm.host_scripts || []).forEach(s => scripts.push(["host", s]));
  if (scripts.length) {
    h += `<h4 style="margin-top:14px;font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:var(--muted)">Script output</h4>`;
    h += scripts.map(([loc, s]) => `<div style="margin-bottom:8px"><code>${esc(loc)} ${esc(s.id)}</code><pre class="nmapout">${esc(s.output)}</pre></div>`).join("");
  }
  if (nm.warnings?.length) h += `<div class="muted" style="font-size:12px;margin-top:8px">nmap notices: ${esc(nm.warnings.join(" · "))}</div>`;
  return h;
}
function verStr(p) {
  let o = p.product || "";
  if (p.version) o += (o ? " " : "") + p.version;
  if (p.extra_info) o += ` (${p.extra_info})`;
  return o;
}

/* HTTP response header analysis (Active Metadata) */
function headerTable(list) {
  const rows = list.slice().sort((a, b) => sevRank(a.severity) - sevRank(b.severity) || a.header.localeCompare(b.header));
  return `<h3>Security headers</h3><div class="tbl scroll"><table><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Assessment</th></tr></thead><tbody>` +
    rows.map(x => `<tr><td><b>${esc(x.header)}</b></td><td><span class="tag ${sevCls(x.severity)}">${esc(x.severity)}</span> ${x.present ? "" : '<small class="muted">absent</small>'}</td><td class="wrap"><small class="muted">${esc(x.value || "")}</small></td><td class="muted">${esc(x.note)}</td></tr>`).join("") +
    `</tbody></table></div>`;
}
