/* ThreatLens UI enhancements (ADR 0011). Served from 'self' under the strict CSP:
   no inline code, no eval, no third-party scripts. Every page works without this
   file; it adds live streaming, in-page actions, row selection and filtering.
   It only places HTML the server rendered (escaped) into elements by id. */
(() => {
  "use strict";
  document.documentElement.classList.add("js");

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  // ── streams: newline-delimited JSON, each line {ops, progress?, done?, error?} ──
  function apply(ops) {
    for (const op of ops || []) {
      const el = document.getElementById(op.id);
      if (!el) continue;
      if (op.op === "replace") el.outerHTML = op.html;
      else if (op.op === "append") el.insertAdjacentHTML("beforeend", op.html);
    }
  }

  async function stream(url, init, onLine) {
    const res = await fetch(url, Object.assign({ credentials: "same-origin", headers: { Accept: "application/x-ndjson" } }, init));
    if (!res.ok) {
      let msg = res.status + " " + res.statusText;
      try { const j = await res.json(); if (j && j.detail) msg = typeof j.detail === "string" ? j.detail : msg; } catch (_) { /* not JSON */ }
      throw new Error(msg);
    }
    const reader = res.body.getReader();
    const dec = new TextDecoder();
    let buf = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buf += dec.decode(value, { stream: true });
      let i;
      while ((i = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, i).trim();
        buf = buf.slice(i + 1);
        if (line) onLine(JSON.parse(line));
      }
    }
  }

  function alertIn(el, msg) {
    if (!el) return;
    const div = document.createElement("div");
    div.className = "alert";
    div.setAttribute("role", "alert");
    div.textContent = msg;
    el.replaceChildren(div);
  }

  // ── verify one value, live ──
  let verifyCtl = null;
  let verifyUrl = null;
  function liveVerify(url) {
    verifyUrl = url;
    if (verifyCtl) verifyCtl.abort();
    const ctl = new AbortController();
    verifyCtl = ctl;
    stream(url, { signal: ctl.signal }, (msg) => {
      apply(msg.ops);
      if (msg.error) alertIn($("#verify-body"), msg.error);
    }).catch((e) => {
      if (e.name !== "AbortError") alertIn($("#verify-body"), "The lookup failed: " + e.message);
    });
  }

  const live = $("[data-stream]");
  if (live) liveVerify(live.dataset.stream);

  // ── bulk check, live ──
  function applyFilter() {
    const sel = $("select[data-filter]");
    const want = sel ? sel.value : "all";
    for (const tr of $$("#bulk-rows tr.brow")) {
      const v = tr.dataset.verdict;
      const show = want === "all" || v === want || (want === "threats" && (v === "malicious" || v === "suspicious"));
      tr.hidden = !show;
    }
  }

  const RANK = { malicious: 0, suspicious: 1, unknown: 2, benign: 3 };
  function sortRows() {
    // rows arrive as each check finishes; once all are in, list the worst first
    const body = $("#bulk-rows");
    if (!body) return;
    const score = (tr) => Number(($(".num b", tr) || {}).textContent || 0);
    const rows = $$("tr.brow", body).sort((a, b) =>
      (RANK[a.dataset.verdict] ?? 9) - (RANK[b.dataset.verdict] ?? 9) || score(b) - score(a));
    body.append(...rows);
  }

  let bulkCtl = null;
  function bulkCheck(form, submitter) {
    if (bulkCtl) bulkCtl.abort();
    const ctl = new AbortController();
    bulkCtl = ctl;
    const fd = new FormData(form, submitter);
    const target = $("#bulk-results");
    if (target) {
      target.hidden = false;
      target.className = "panel bulk";
      target.innerHTML = '<p class="muted" role="status">Extracting indicators…</p>';
    }
    stream("/ui/lookup/stream", { method: "POST", body: fd, signal: ctl.signal }, (msg) => {
      apply(msg.ops);
      if (msg.progress) {
        const p = $("#bulk-progress");
        if (p) { p.max = msg.progress[1]; p.value = msg.progress[0]; }
      }
      if (msg.done) sortRows();
      applyFilter();
      if (msg.error) alertIn($("#bulk-summary"), msg.error);
    }).catch((e) => {
      if (e.name !== "AbortError") alertIn($("#bulk-results"), e.message);
    });
  }

  function openPane(tr) {
    for (const r of $$("#bulk-rows tr.selected")) r.classList.remove("selected");
    tr.classList.add("selected");
    const results = $("#bulk-results");
    const tlp = (results && results.dataset.tlp) || "TLP:GREEN";
    const q = new URLSearchParams({ q: tr.dataset.value, tlp, providers: "false" });
    const full = $("#pane-full");
    if (full) { full.href = "/ui/verify?" + new URLSearchParams({ q: tr.dataset.value, tlp, providers: "true", live: "true" }); full.hidden = false; }
    const body = $("#verify-body");
    if (body) body.innerHTML = '<p class="muted" role="status">Loading…</p>';
    liveVerify("/ui/verify/stream?" + q.toString());
  }

  // ── in-page actions (Block / Flag malicious / Not malicious) ──
  function rowsFor(values) {
    const want = new Set(values);
    return $$("#bulk-rows tr.brow").filter((tr) => want.has(tr.dataset.value));
  }

  function addPill(values, cls, text) {
    for (const tr of rowsFor(values)) {
      const env = $("[data-env]", tr);
      if (env && !$$(".pill", env).some((p) => p.textContent === text)) {
        const s = document.createElement("span");
        s.className = "pill " + cls;
        s.textContent = text;
        env.append(s);
      }
    }
  }

  function outcomeEl(form) {
    const box = form.closest(".vcard") || form.closest("#bulk-results") || form.parentElement;
    return box ? $("[data-outcome]", box) : null;
  }

  function report(form, action, data) {
    const out = outcomeEl(form);
    let msg;
    if (action.endsWith("/ui/blocklist")) {
      const ok = (data.created || []).map((c) => c.input);
      addPill(ok, "cyan", "blocked");
      msg = ok.length + " blocked (monitor)";
      if ((data.refused || []).length) msg += " · refused: " + data.refused.map((r) => r.why).join("; ");
    } else {
      const ok = (data.done || []).map((d) => d.value);
      const tp = data.verdict === "tp";
      addPill((data.done || []).map((d) => d.input || d.value), tp ? "pink" : "gray", tp ? "flagged" : "not malicious");
      msg = ok.length + (tp ? " flagged malicious" : " marked not malicious");
      if ((data.refused || []).length) msg += " · refused: " + data.refused.map((r) => r.why).join("; ");
    }
    if (out) out.textContent = msg;
  }

  async function submitJson(form, submitter) {
    const action = (submitter && submitter.getAttribute("formaction")) || form.getAttribute("action");
    const fd = new FormData(form, submitter);
    const out = outcomeEl(form);
    if (!fd.getAll("values").length) { if (out) out.textContent = "Select at least one row."; return; }
    if (submitter) submitter.disabled = true;
    try {
      const res = await fetch(action, { method: "POST", body: fd, credentials: "same-origin", headers: { Accept: "application/json" } });
      let data = {};
      try { data = await res.json(); } catch (_) { data = { detail: res.status + " " + res.statusText }; }
      if (!res.ok && !data.refused) { if (out) out.textContent = data.detail || "Failed."; return; }
      report(form, action, data);
      if (form.matches("form[data-json]") && res.ok && verifyUrl) {
        // an action on the analysis itself: re-run it (cached answers, fast) so every card shows the new state
        setTimeout(() => liveVerify(verifyUrl), 400);
      }
    } finally {
      if (submitter) submitter.disabled = false;
    }
  }

  // ── events ──
  document.addEventListener("submit", (ev) => {
    const form = ev.target;
    const sub = ev.submitter;
    if (form.matches("form[data-verify]")) {
      ev.preventDefault();
      const p = new URLSearchParams(new FormData(form));
      p.set("live", "true");
      location.assign("/ui/verify?" + p.toString());
      return;
    }
    if (form.matches("form[data-bulk-check]")) {
      if (sub && sub.value === "csv") return; // the CSV download is a normal form post
      ev.preventDefault();
      bulkCheck(form, sub);
      return;
    }
    const action = (sub && sub.getAttribute("formaction")) || form.getAttribute("action") || "";
    if (form.matches("form[data-json]") || (form.id === "bulk-actions" && !action.endsWith("/ui/cases/add"))) {
      ev.preventDefault();
      submitJson(form, sub);
    }
  });

  // "Copy refanged": the only place a live value leaves the page, and only on an explicit click
  const refang = (s) => s.replace(/\[:\/\/\]/g, "://").replace(/\[\.\]/g, ".").replace(/\[:\]/g, ":")
    .replace(/\[@\]/g, "@").replace(/^hxxp/i, "http").replace(/^fxp/i, "ftp");

  async function copyRefanged(btn) {
    const label = btn.textContent;
    try {
      await navigator.clipboard.writeText(refang(btn.dataset.copy || ""));
      btn.textContent = "Copied";
    } catch (_) {
      btn.textContent = "Copy failed";
    }
    setTimeout(() => { btn.textContent = label; }, 1500);
  }

  document.addEventListener("click", (ev) => {
    const copy = ev.target.closest("button[data-copy]");
    if (copy) { copyRefanged(copy); return; }
    const pick = ev.target.closest("[data-select]");
    if (pick) {
      const mode = pick.dataset.select;
      for (const tr of $$("#bulk-rows tr.brow")) {
        const cb = $("input[type=checkbox]", tr);
        if (!cb) continue;
        const v = tr.dataset.verdict;
        cb.checked = mode === "threats" ? v === "malicious" || v === "suspicious" : mode === "malicious" ? v === "malicious" : false;
      }
      return;
    }
    const tr = ev.target.closest("#bulk-rows tr.brow");
    if (tr && !ev.target.closest("input, a, button, label, select")) openPane(tr);
  });

  document.addEventListener("keydown", (ev) => {
    const tr = ev.target.closest && ev.target.closest("#bulk-rows tr.brow");
    if (tr && ev.target === tr && (ev.key === "Enter" || ev.key === " ")) { ev.preventDefault(); openPane(tr); }
  });

  document.addEventListener("change", (ev) => {
    if (ev.target.matches("select[data-filter]")) applyFilter();
  });
})();
