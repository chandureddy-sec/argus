import { ChevronLeft, ChevronRight, FileCode2, Globe, Link2, Search, Server, type LucideIcon } from "lucide-react";
import { useMemo, useState } from "react";
import type { IocType, Row } from "../data/sample";
import { Card, CardHead, Select } from "./ui";

const TYPE: Record<IocType, { icon: LucideIcon; label: string }> = {
  ip: { icon: Server, label: "IP address" },
  domain: { icon: Globe, label: "Domain" },
  url: { icon: Link2, label: "URL" },
  hash: { icon: FileCode2, label: "File hash" },
};
const PAGE = 8;

/** Defanged values stay inert when copied; the brackets are dimmed so they read normally. */
function Ioc({ value }: { value: string }) {
  const parts = value.split(/(\[\.\]|\[:\]|hxxps?)/);
  return (
    <span className="font-mono text-[13px] text-ink">
      {parts.map((p, i) =>
        /^\[|^hxxp/.test(p) ? (
          <span key={i} className="text-ink-faint">
            {p}
          </span>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </span>
  );
}

function Score({ n }: { n: number }) {
  const tone = n >= 60 ? "text-down" : n >= 30 ? "text-warn" : "text-ink-muted";
  return (
    <div className="flex items-center justify-end gap-2.5">
      <div className="hidden h-1.5 w-16 overflow-hidden rounded-full bg-line md:block">
        <div className={`h-full rounded-full ${n >= 60 ? "bg-down" : n >= 30 ? "bg-warn" : "bg-ink-faint"}`} style={{ width: `${n}%` }} />
      </div>
      <span className={`w-7 text-right font-semibold tabular-nums ${tone}`}>{n}</span>
    </div>
  );
}

export default function DataTable({ rows }: { rows: Row[] }) {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("All statuses");
  const [type, setType] = useState("All types");
  const [page, setPage] = useState(0);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase().replace(/\[\.\]/g, ".");
    return rows.filter(
      (r) =>
        (status === "All statuses" || r.status === status) &&
        (type === "All types" || TYPE[r.type].label === type) &&
        (!needle || `${r.value} ${r.source} ${r.location}`.toLowerCase().replace(/\[\.\]/g, ".").includes(needle)),
    );
  }, [rows, q, status, type]);
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE));
  const shown = filtered.slice(page * PAGE, page * PAGE + PAGE);
  const reset = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPage(0);
  };

  return (
    <Card delay={280} className="!p-0">
      <div className="p-5 pb-0 sm:p-6 sm:pb-0">
        <CardHead title="Latest indicators" sub="Known-bad values from your feeds, scored 0–100 and matched locally">
          <button className="btn-ghost h-8 text-[13px]">Export CSV</button>
        </CardHead>
        <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center">
          <label className="relative flex-1 sm:max-w-xs">
            <span className="sr-only">Filter indicators</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input value={q} onChange={(e) => reset(setQ)(e.target.value)} className="ctl h-8 w-full pl-9 text-[13px]" placeholder="Filter by value, source, country" />
          </label>
          <div className="flex gap-2">
            <Select value={status} options={["All statuses", "Active", "Expired"]} onChange={reset(setStatus)} label="Status" />
            <Select value={type} options={["All types", ...Object.values(TYPE).map((t) => t.label)]} onChange={reset(setType)} label="Type" />
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full min-w-[820px] text-left text-[13.5px]">
          <thead>
            <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
              <th className="w-12 py-3 pl-6 font-medium">#</th>
              <th className="py-3 font-medium">Indicator</th>
              <th className="py-3 font-medium">Source</th>
              <th className="py-3 font-medium">Date</th>
              <th className="py-3 font-medium">Location</th>
              <th className="py-3 font-medium">Status</th>
              <th className="py-3 pr-6 text-right font-medium">Score</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((r) => {
              const T = TYPE[r.type];
              return (
                <tr key={r.id} className="border-b border-line/70 transition-colors odd:bg-white/[0.012] hover:bg-accent/[0.06]">
                  <td className="py-3.5 pl-6 text-ink-faint tabular-nums">{r.id}</td>
                  <td className="py-3.5">
                    <div className="flex items-center gap-3">
                      <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-accent/10 text-accent-soft ring-1 ring-accent/20" title={T.label}>
                        <T.icon className="h-4 w-4" />
                      </span>
                      <div className="min-w-0">
                        <Ioc value={r.value} />
                        <p className="text-[12px] text-ink-faint">{T.label}</p>
                      </div>
                    </div>
                  </td>
                  <td className="py-3.5 text-ink-muted">{r.source}</td>
                  <td className="py-3.5 whitespace-nowrap text-ink-muted">{r.date}</td>
                  <td className="py-3.5 text-ink-muted">{r.location}</td>
                  <td className="py-3.5">
                    <span
                      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[12px] font-medium ring-1 ${
                        r.status === "Active" ? "bg-up/10 text-up ring-up/20" : "bg-down/10 text-down ring-down/20"
                      }`}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${r.status === "Active" ? "bg-up" : "bg-down"}`} />
                      {r.status}
                    </span>
                  </td>
                  <td className="py-3.5 pr-6">
                    <Score n={r.score} />
                  </td>
                </tr>
              );
            })}
            {!shown.length && (
              <tr>
                <td colSpan={7} className="py-12 text-center text-ink-muted">
                  Nothing matches these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <footer className="flex items-center justify-between gap-3 px-6 py-4 text-[13px] text-ink-muted">
        <span>
          Showing <b className="text-ink">{filtered.length ? page * PAGE + 1 : 0}</b>–<b className="text-ink">{Math.min(filtered.length, (page + 1) * PAGE)}</b> of{" "}
          <b className="text-ink">{filtered.length}</b>
        </span>
        <div className="flex items-center gap-1.5">
          <button className="btn-ghost h-8 w-8 !px-0" disabled={page === 0} onClick={() => setPage(page - 1)} aria-label="Previous page">
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="px-2 tabular-nums">
            {page + 1} / {pages}
          </span>
          <button className="btn-ghost h-8 w-8 !px-0" disabled={page >= pages - 1} onClick={() => setPage(page + 1)} aria-label="Next page">
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </footer>
    </Card>
  );
}
