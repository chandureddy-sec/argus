/* ReconX visualisations: infrastructure graph and geo map for the detail view.
 * Uses helpers from index.html / detail.js: esc, reportURLs, DETAIL, EV, pill.
 */

/* ───────── shared SVG pan / zoom ───────── */
function panZoom(svg, view, opts) {
  // view = {x, y, w, h}; mutated in place. opts.min/max bound the zoom.
  const o = Object.assign({ min: 0.2, max: 12 }, opts || {});
  const base = { ...view };
  const apply = () => svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
  const toSvg = (cx, cy) => {
    const r = svg.getBoundingClientRect();
    return [view.x + (cx - r.left) / r.width * view.w, view.y + (cy - r.top) / r.height * view.h];
  };
  const zoomAt = (f, px, py) => {
    const nw = view.w * f;
    if (nw < base.w / o.max || nw > base.w / o.min) return;
    view.x = px - (px - view.x) * f; view.y = py - (py - view.y) * f;
    view.w = nw; view.h = view.h * f; apply();
  };
  // Ctrl/⌘ + wheel zooms; a plain wheel keeps scrolling the page.
  svg.addEventListener("wheel", e => {
    if (!e.ctrlKey && !e.metaKey) return;
    e.preventDefault();
    const [px, py] = toSvg(e.clientX, e.clientY);
    zoomAt(e.deltaY < 0 ? 0.85 : 1 / 0.85, px, py);
  }, { passive: false });
  let drag = null;
  svg.addEventListener("pointerdown", e => {
    if (e.target.closest("[data-node]")) return; // node drags are handled by the graph
    drag = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
    svg.setPointerCapture(e.pointerId); svg.style.cursor = "grabbing";
  });
  svg.addEventListener("pointermove", e => {
    if (!drag) return;
    const r = svg.getBoundingClientRect();
    view.x = drag.vx - (e.clientX - drag.x) / r.width * view.w;
    view.y = drag.vy - (e.clientY - drag.y) / r.height * view.h; apply();
  });
  const end = () => { drag = null; svg.style.cursor = ""; };
  svg.addEventListener("pointerup", end); svg.addEventListener("pointercancel", end);
  apply();
  const zoomCenter = f => zoomAt(f, view.x + view.w / 2, view.y + view.h / 2);
  // fitTo makes a region the new "home" view, padded and kept at the
  // canvas's aspect ratio.
  const fitTo = (x, y, w, h) => {
    const ratio = base.w / base.h, pad = 40;
    w += pad * 2; h += pad * 2; x -= pad; y -= pad;
    if (w / h > ratio) { const nh = w / ratio; y -= (nh - h) / 2; h = nh; } else { const nw = h * ratio; x -= (nw - w) / 2; w = nw; }
    Object.assign(base, { x, y, w, h }); Object.assign(view, base); apply();
  };
  return { reset() { Object.assign(view, base); apply(); }, fitTo, zoomIn: () => zoomCenter(0.75), zoomOut: () => zoomCenter(1 / 0.75), toSvg, apply };
}

/* ───────── Infrastructure graph ───────── */
const GKIND = {
  domain: ["Domain", "#a7e9c6", 13], host: ["Subdomain", "#ededef", 6], cname: ["CNAME target", "#c4a7ff", 6],
  ip: ["IP", "#8fb8ff", 6], asn: ["ASN", "#f0c36d", 9], provider: ["Provider (inferred)", "#f0a39d", 10],
  ns: ["Nameserver", "#9a9aa0", 6], mx: ["Mail server", "#9a9aa0", 6],
};
const GFLAG = { kev: "#ff6b6b", "high-interest": "#ff6b6b", dangling: "#f0c36d", exposed: "#f0c36d", new: "#8fb8ff", changed: "#f0c36d", "routing-conflict": "#f0c36d", "not-resolving": "#6c6c72" };
let GRAPH = null; // {data, nodes, edges, sim, ...}

function tabGraph() {
  return `<div class="toolbar"><div class="chips" id="gKinds">${Object.entries(GKIND).map(([k, [l, c]]) =>
      `<button class="chip2 on" data-k="${k}"><span class="sw" style="background:${c};margin-right:5px"></span>${l} <span data-c="${k}"></span></button>`).join("")}</div>
    <div class="tright"><input id="gQ" class="filter" type="search" placeholder="Find node…">
      <label class="ck" style="color:var(--muted);margin:0 6px"><input type="checkbox" id="gHist"> include not-resolving hosts</label>
      <button class="ghost" id="gFit">Reset view</button>
      <div class="dd"><button type="button">⬇ Export ▾</button><div class="menu">
        <a href="${reportURLs(DETAIL.kind, DETAIL.id).dl("graphml")}" download>GraphML (Gephi, yEd) <span>.graphml</span></a>
        <a href="${reportURLs(DETAIL.kind, DETAIL.id).dl("graph")}" download>Graph JSON <span>.json</span></a></div></div></div></div>
    <div class="evlegend">Edges: solid = ${EV.observed} DNS · dashed = ${EV.enriched} routing · dotted = ${EV.inferred} provider. Ring colours flag KEV / high interest (red), exposure / dangling / changes (amber), new (blue). Ctrl + scroll or the +/− buttons zoom; drag to pan or move nodes; click a node to focus its neighbourhood.</div>
    <div class="gwrap"><svg id="gSvg" class="gsvg"></svg><div class="gzoom"><button type="button" id="gZin" title="Zoom in">+</button><button type="button" id="gZout" title="Zoom out">−</button></div><div id="gTip" class="gtip hidden"></div><div id="gInfo" class="ginfo hidden"></div></div>
    <div class="muted" id="gMeta" style="font-size:12px;margin-top:8px"></div>`;
}

async function wireGraph() {
  const load = async () => {
    const svg = document.getElementById("gSvg");
    svg.innerHTML = `<text x="20" y="30" fill="#9a9aa0" font-size="13">Building graph…</text>`;
    const hist = document.getElementById("gHist").checked ? "1" : "0";
    const base = reportURLs(DETAIL.kind, DETAIL.id).html.replace(/\/html$/, "");
    try {
      const r = await fetch(`${base}/graph?historical=${hist}&max=250`);
      if (!r.ok) throw new Error((await r.text()).trim());
      drawGraph(await r.json());
    } catch (e) { svg.innerHTML = `<text x="20" y="30" fill="#f0a39d" font-size="13">${esc(e.message || "Graph unavailable")}</text>`; }
  };
  document.getElementById("gHist").onchange = load;
  document.getElementById("gFit").onclick = () => GRAPH && GRAPH.pz.reset();
  document.getElementById("gZin").onclick = () => GRAPH && GRAPH.pz.zoomIn();
  document.getElementById("gZout").onclick = () => GRAPH && GRAPH.pz.zoomOut();
  document.getElementById("gQ").oninput = e => GRAPH && highlightSearch(e.target.value.trim().toLowerCase());
  document.querySelectorAll("#gKinds .chip2").forEach(b => b.onclick = () => { b.classList.toggle("on"); GRAPH && applyKindFilter(); });
  await load();
}

function drawGraph(data) {
  if (GRAPH?.raf) cancelAnimationFrame(GRAPH.raf);
  const svg = document.getElementById("gSvg");
  const W = 1200, H = 760;
  const nodes = data.nodes.map((n, i) => {
    const a = i * 2.399963, rad = 30 + 9 * Math.sqrt(i); // phyllotaxis start: stable, untangled
    return { ...n, x: W / 2 + rad * Math.cos(a), y: H / 2 + rad * Math.sin(a), vx: 0, vy: 0, r: (GKIND[n.kind]?.[2] || 6) + Math.min(10, Math.sqrt(n.weight || 1) * 1.6) };
  });
  const byId = new Map(nodes.map(n => [n.id, n]));
  const edges = data.edges.map(e => ({ ...e, s: byId.get(e.from), t: byId.get(e.to) })).filter(e => e.s && e.t);
  const adj = new Map(nodes.map(n => [n.id, new Set()]));
  edges.forEach(e => { adj.get(e.s.id).add(e.t.id); adj.get(e.t.id).add(e.s.id); });
  const root = nodes.find(n => n.kind === "domain");
  if (root) { root.x = W / 2; root.y = H / 2; root.fixed = true; }

  const counts = {};
  nodes.forEach(n => counts[n.kind] = (counts[n.kind] || 0) + 1);
  document.querySelectorAll("#gKinds [data-c]").forEach(s => s.textContent = counts[s.dataset.c] || 0);
  document.getElementById("gMeta").textContent = `${nodes.length} nodes · ${edges.length} edges` +
    (data.truncated ? ` · showing the 250 highest-interest hosts (${data.omitted_hosts} more in the GraphML export)` : "");

  const dash = { observed: "", enriched: "5 4", inferred: "2 4" };
  svg.innerHTML = `<g id="gEdges">${edges.map((e, i) => `<line data-e="${i}" stroke="#4a4a50" stroke-width="1" stroke-dasharray="${dash[e.evidence] || ""}"/>`).join("")}</g>
    <g id="gNodes">${nodes.map((n, i) => {
      const ring = (n.flags || []).map(f => GFLAG[f]).find(Boolean);
      return `<g data-node="${i}" class="gn"><circle r="${n.r}" fill="${GKIND[n.kind]?.[1] || "#ccc"}" stroke="${ring || "#161617"}" stroke-width="${ring ? 3 : 1.5}"/>` +
        `<text dy="${n.r + 11}" text-anchor="middle">${esc(shortLabel(n))}</text></g>`;
    }).join("")}</g>`;
  const lineEls = [...svg.querySelectorAll("#gEdges line")], nodeEls = [...svg.querySelectorAll("#gNodes .gn")];

  const view = { x: 0, y: 0, w: W, h: H };
  const pz = panZoom(svg, view);
  GRAPH = { data, nodes, edges, adj, lineEls, nodeEls, pz, focus: null };

  // Labels only for important nodes until zoomed in, to keep large graphs legible.
  const labelAll = nodes.length <= 80;
  nodeEls.forEach((el, i) => { const n = nodes[i]; if (!labelAll && n.kind !== "domain" && n.kind !== "provider" && n.kind !== "asn" && !(n.flags || []).length) el.classList.add("nolabel"); });

  // Force simulation with a spatial grid for repulsion (O(n) per tick).
  let alpha = 1;
  const step = () => {
    const cell = 120, grid = new Map();
    nodes.forEach(n => { const k = `${Math.floor(n.x / cell)},${Math.floor(n.y / cell)}`; (grid.get(k) || grid.set(k, []).get(k)).push(n); });
    nodes.forEach(a => {
      const gx = Math.floor(a.x / cell), gy = Math.floor(a.y / cell);
      for (let dx = -1; dx <= 1; dx++) for (let dy = -1; dy <= 1; dy++) {
        const list = grid.get(`${gx + dx},${gy + dy}`); if (!list) continue;
        for (const b of list) {
          if (a === b) continue;
          let x = a.x - b.x, y = a.y - b.y, d2 = x * x + y * y || 0.01;
          if (d2 > cell * cell) continue;
          const f = 1400 / d2 * alpha; a.vx += x * f * 0.05; a.vy += y * f * 0.05;
        }
      }
    });
    edges.forEach(e => {
      const x = e.t.x - e.s.x, y = e.t.y - e.s.y, d = Math.sqrt(x * x + y * y) || 1;
      const want = e.rel === "subdomain" ? 90 : 60, f = (d - want) / d * 0.06 * alpha;
      e.s.vx += x * f; e.s.vy += y * f; e.t.vx -= x * f; e.t.vy -= y * f;
    });
    nodes.forEach(n => {
      n.vx += (W / 2 - n.x) * 0.0015 * alpha; n.vy += (H / 2 - n.y) * 0.0015 * alpha;
      if (n.fixed || n.drag) { n.vx = n.vy = 0; return; }
      n.vx *= 0.6; n.vy *= 0.6; n.x += Math.max(-20, Math.min(20, n.vx)); n.y += Math.max(-20, Math.min(20, n.vy));
    });
  };
  // Animated settling after a node is dragged.
  const animate = () => {
    step(); render(); alpha *= 0.985;
    if (alpha > 0.02) GRAPH.raf = requestAnimationFrame(animate);
  };
  const render = () => {
    lineEls.forEach((l, i) => { const e = edges[i]; l.setAttribute("x1", e.s.x); l.setAttribute("y1", e.s.y); l.setAttribute("x2", e.t.x); l.setAttribute("y2", e.t.y); });
    nodeEls.forEach((g, i) => g.setAttribute("transform", `translate(${nodes[i].x},${nodes[i].y})`));
  };
  const fit = () => {
    const xs = nodes.map(n => n.x), ys = nodes.map(n => n.y);
    const x0 = Math.min(...xs), y0 = Math.min(...ys), w = Math.max(...xs) - x0, h = Math.max(...ys) - y0;
    const min = 420; // don't blow a 3-node graph up to fill the canvas
    pz.fitTo(x0 - Math.max(0, min - w) / 2, y0 - Math.max(0, min * 0.63 - h) / 2, Math.max(w, min), Math.max(h, min * 0.63));
  };
  GRAPH.fit = fit;
  GRAPH.reheat = () => { alpha = Math.max(alpha, 0.3); cancelAnimationFrame(GRAPH.raf); GRAPH.raf = requestAnimationFrame(animate); };
  // Lay the graph out up front (fast with the grid) so it appears settled
  // and framed, rather than animating in from a tangle.
  while (alpha > 0.02) { step(); alpha *= 0.985; }
  render(); fit();

  // Interaction: hover tooltip, drag nodes, click to focus.
  const tip = document.getElementById("gTip"), wrap = svg.parentElement;
  nodeEls.forEach((el, i) => {
    const n = nodes[i];
    el.addEventListener("pointerenter", () => {
      tip.innerHTML = `<b>${esc(n.label)}</b><div class="muted">${esc(GKIND[n.kind]?.[0] || n.kind)}${n.weight > 1 ? ` · ${n.weight} hosts` : ""}</div>${n.detail ? `<div>${esc(n.detail)}</div>` : ""}${(n.flags || []).length ? `<div>${n.flags.map(f => `<small class="ind">${esc(f)}</small>`).join(" ")}</div>` : ""}`;
      tip.classList.remove("hidden");
    });
    el.addEventListener("pointermove", e => { const r = wrap.getBoundingClientRect(); tip.style.left = (e.clientX - r.left + 14) + "px"; tip.style.top = (e.clientY - r.top + 10) + "px"; });
    el.addEventListener("pointerleave", () => tip.classList.add("hidden"));
    let moved = false;
    el.addEventListener("pointerdown", e => { e.stopPropagation(); n.drag = true; moved = false; el.setPointerCapture(e.pointerId); });
    el.addEventListener("pointermove", e => {
      if (!n.drag) return; moved = true;
      const [x, y] = pz.toSvg(e.clientX, e.clientY); n.x = x; n.y = y; render();
    });
    el.addEventListener("pointerup", () => { n.drag = false; if (moved) { n.fixed = n.kind === "domain"; GRAPH.reheat(); } else focusNode(i); });
  });
  svg.addEventListener("click", e => { if (!e.target.closest("[data-node]")) focusNode(null); });
  applyKindFilter();
}

function shortLabel(n) {
  const t = DETAIL?.rep?.target?.value;
  if (n.kind === "host" && t && n.label.endsWith("." + t)) return n.label.slice(0, -(t.length + 1));
  return n.label.length > 28 ? n.label.slice(0, 26) + "…" : n.label;
}

function focusNode(i) {
  const G = GRAPH; if (!G) return;
  const info = document.getElementById("gInfo");
  G.focus = i;
  if (i === null) {
    G.nodeEls.forEach(el => el.classList.remove("dim", "hl"));
    G.lineEls.forEach(el => el.classList.remove("dim", "hl"));
    info.classList.add("hidden");
    return;
  }
  const n = G.nodes[i], near = G.adj.get(n.id);
  G.nodeEls.forEach((el, k) => { const m = G.nodes[k]; const on = k === i || near.has(m.id); el.classList.toggle("dim", !on); el.classList.toggle("hl", on); });
  G.lineEls.forEach((el, k) => { const e = G.edges[k]; const on = e.s === n || e.t === n; el.classList.toggle("dim", !on); el.classList.toggle("hl", on); });
  const links = G.edges.filter(e => e.s === n || e.t === n).map(e => {
    const other = e.s === n ? e.t : e.s, dir = e.s === n ? "→" : "←";
    return `<div class="cl"><span>${dir} ${esc(e.rel.replace("_", " "))} <b>${esc(other.label)}</b></span><small class="muted">${esc(e.evidence)}</small></div>`;
  }).join("");
  info.innerHTML = `<div style="display:flex;justify-content:space-between;gap:8px"><b>${esc(n.label)}</b><a href="#" onclick="focusNode(null);return false" class="muted">✕</a></div>
    <div class="muted" style="font-size:12px;margin-bottom:6px">${esc(GKIND[n.kind]?.[0] || n.kind)}${n.detail ? " · " + esc(n.detail) : ""}</div>${links}`;
  info.classList.remove("hidden");
}

function applyKindFilter() {
  const G = GRAPH; if (!G) return;
  const on = new Set([...document.querySelectorAll("#gKinds .chip2.on")].map(b => b.dataset.k));
  G.nodeEls.forEach((el, i) => el.style.display = on.has(G.nodes[i].kind) ? "" : "none");
  G.lineEls.forEach((el, i) => el.style.display = on.has(G.edges[i].s.kind) && on.has(G.edges[i].t.kind) ? "" : "none");
}

function highlightSearch(q) {
  const G = GRAPH; if (!G) return;
  if (!q) { G.nodeEls.forEach(el => el.classList.remove("match")); return; }
  let first = null;
  G.nodeEls.forEach((el, i) => { const m = G.nodes[i].label.toLowerCase().includes(q); el.classList.toggle("match", m); if (m && first === null) first = i; });
  if (first !== null) focusNode(first);
}

/* ───────── Geo map ───────── */
let WORLD_PATH = null;

function tabMap() {
  return `<div class="evlegend">${EV.enriched} Locations are ip-api.com estimates — often a city or country centroid; anycast/CDN IPs show a single point of presence. Circle size = IPs at that spot (Ctrl + scroll or +/− to zoom); colour: <span style="color:#86ddb0">●</span> no reported exposure · <span style="color:#f0c36d">●</span> open ports in Shodan · <span style="color:#ff6b6b">●</span> a CISA KEV CVE reported.</div>
    <div class="gwrap"><svg id="mSvg" class="gsvg msvg"></svg><div class="gzoom"><button type="button" id="mZin" title="Zoom in">+</button><button type="button" id="mZout" title="Zoom out">−</button></div><div id="mTip" class="gtip hidden"></div></div>
    <div class="toolbar"><div class="muted" id="mMeta" style="font-size:12px"></div><button class="ghost" id="mFit">Reset view</button></div>
    <div id="mList"></div>`;
}

async function wireMap() {
  const svg = document.getElementById("mSvg");
  const base = reportURLs(DETAIL.kind, DETAIL.id).html.replace(/\/html$/, "");
  let geo;
  try {
    const [w, g] = await Promise.all([WORLD_PATH ? Promise.resolve(WORLD_PATH) : fetch("/api/worldmap").then(r => r.text()), fetch(`${base}/geo`).then(r => r.json())]);
    WORLD_PATH = w; geo = g;
  } catch (e) { svg.outerHTML = `<div class="errbox">Map data unavailable.</div>`; return; }
  const pts = geo.points || [];
  svg.innerHTML = `<path d="${WORLD_PATH}" fill="#2f2f33"/>` +
    pts.slice().reverse().map((p, k) => {
      const i = pts.length - 1 - k, r = 3.5 + 2.4 * Math.sqrt(p.ips.length);
      const fill = p.kev ? "#ff6b6b" : p.exposed ? "#f0c36d" : "#86ddb0";
      return `<circle data-p="${i}" cx="${p.x}" cy="${p.y}" r="${r}" fill="${fill}" fill-opacity=".78" stroke="#161617" stroke-width=".8" style="cursor:pointer"/>`;
    }).join("");
  const pz = panZoom(svg, { x: 0, y: 30, w: 1000, h: 410 }, { min: 1, max: 20 });
  document.getElementById("mFit").onclick = () => pz.reset();
  document.getElementById("mZin").onclick = () => pz.zoomIn();
  document.getElementById("mZout").onclick = () => pz.zoomOut();
  const tip = document.getElementById("mTip"), wrap = svg.parentElement;
  svg.querySelectorAll("circle[data-p]").forEach(c => {
    const p = pts[+c.dataset.p];
    c.addEventListener("pointerenter", () => { tip.innerHTML = geoTip(p); tip.classList.remove("hidden"); });
    c.addEventListener("pointermove", e => { const r = wrap.getBoundingClientRect(); tip.style.left = (e.clientX - r.left + 14) + "px"; tip.style.top = (e.clientY - r.top + 10) + "px"; });
    c.addEventListener("pointerleave", () => tip.classList.add("hidden"));
  });
  document.getElementById("mMeta").textContent = pts.length
    ? `${pts.length} location${pts.length === 1 ? "" : "s"} · ${pts.reduce((a, p) => a + p.ips.length, 0)} IPs${geo.missing ? ` · ${geo.missing} IP(s) without coordinates` : ""}`
    : (geo.missing ? `None of the ${geo.missing} IPs have coordinates — scans before this version didn't record them; run a new scan.` : "No IPs to place on the map.");
  document.getElementById("mList").innerHTML = pts.length ? `<div class="tbl scroll"><table><thead><tr><th>Location</th><th class="num">IPs</th><th class="num">Hosts</th><th>Providers</th><th>Addresses</th></tr></thead><tbody>` +
    pts.map(p => `<tr><td><b>${esc(p.place)}</b>${p.kev ? ' <small class="ind" style="color:#ff6b6b">KEV</small>' : p.exposed ? ' <small class="ind">exposed</small>' : ""}</td><td class="num">${p.ips.length}</td><td class="num">${p.hosts}</td><td>${esc((p.providers || []).join(", "))}</td><td class="wrap muted">${esc(p.ips.join(", "))}</td></tr>`).join("") + `</tbody></table></div>` : "";
}

function geoTip(p) {
  return `<b>${esc(p.place)}</b><div class="muted">${p.ips.length} IP${p.ips.length === 1 ? "" : "s"} · ${p.hosts} host${p.hosts === 1 ? "" : "s"}</div>` +
    `${(p.providers || []).length ? `<div>${esc(p.providers.join(", "))}</div>` : ""}<div class="muted" style="font-size:11px">${esc(p.ips.slice(0, 6).join(", "))}${p.ips.length > 6 ? " …" : ""}</div>`;
}
