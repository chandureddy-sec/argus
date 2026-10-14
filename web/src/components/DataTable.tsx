import {
  Bug,
  ChevronLeft,
  ChevronRight,
  FileCode2,
  Globe,
  Link2,
  Mail,
  Search,
  Server,
  Shapes,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { useApi, useDebounced, type Family, type IndicatorRow, type Page } from "../lib/api";
import { Empty, Failed, Skeleton } from "./states";
import { Card, CardHead, Select } from "./ui";

const ICON: Partial<Record<Family, LucideIcon>> = { ip: Server, domain: Globe, url: Link2, hash: FileCode2, cve: Bug, email: Mail };
const TYPES: [string, string][] = [["All types", ""], ["IP addresses", "ip"], ["Domains", "domain"], ["URLs", "url"], ["File hashes", "hash"], ["CVEs", "cve"]];
const STATUSES: [string, string][] = [["All statuses", ""], ["Active", "active"], ["Expired", "expired"], ["Not malicious", "false_positive"], ["Revoked", "revoked"]];
const PILL: Record<IndicatorRow["status"], [string, string]> = {
  active: ["Active", "bg-up/10 text-up ring-up/20"],
  new: ["New", "bg-accent/10 text-accent-soft ring-accent/20"],
  expired: ["Expired", "bg-down/10 text-down ring-down/20"],
  false_positive: ["Not malicious", "bg-ink-faint/15 text-ink-muted ring-line"],
  revoked: ["Revoked", "bg-ink-faint/15 text-ink-muted ring-line"],
};
const SIZE = 8;
const DATE = new Intl.DateTimeFormat("en", { month: "short", day: "2-digit", year: "numeric" });

/** Defanged values stay inert when copied; the brackets are dimmed so they read normally. */
function Ioc({ value }: { value: string }) {
  const parts = value.split(/(\[\.\]|\[:\]|\[@\]|\[:\/\/\]|hxxps?)/);
  return (
    <span className="break-all font-mono text-[13px] text-ink">
      {parts.map((p, i) => (/^\[|^hxxp/.test(p) ? <span key={i} className="text-ink-faint">{p}</span> : <span key={i}>{p}</span>))}
    </span>
  );
}

function Score({ n }: { n: number | null }) {
  if (n === null) return <span className="block text-right text-ink-faint">–</span>;
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

export default function DataTable() {
  const [q, setQ] = useState("");
  const [status, setStatus] = useState("All statuses");
  const [type, setType] = useState("All types");
  const [page, setPage] = useState(1);
  const search = useDebounced(q);
  const params = {
    q: search,
    status: STATUSES.find(([l]) => l === status)?.[1],
    type: TYPES.find(([l]) => l === type)?.[1],
    page,
    size: SIZE,
  };
  const { data, error, loading, reload } = useApi<Page<IndicatorRow>>("indicators", params);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / SIZE));
  const reset = (set: (v: string) => void) => (v: string) => {
    set(v);
    setPage(1);
  };

  return (
    <Card delay={280} className="!p-0">
      <div className="p-5 pb-0 sm:p-6 sm:pb-0">
        <CardHead title="Latest indicators" sub="Known-bad values from your feeds, newest first, scored 0–100 and matched locally">
          <a className="btn-ghost h-8 text-[13px]" href="/ui/indicators">
            Open all
          </a>
        </CardHead>
        <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center">
          <label className="relative flex-1 sm:max-w-xs">
            <span className="sr-only">Filter indicators</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input value={q} onChange={(e) => reset(setQ)(e.target.value)} className="ctl h-8 w-full pl-9 text-[13px]" placeholder="Filter by value (defanged is fine)" />
          </label>
          <div className="flex gap-2">
            <Select value={status} options={STATUSES.map(([l]) => l)} onChange={reset(setStatus)} label="Status" />
            <Select value={type} options={TYPES.map(([l]) => l)} onChange={reset(setType)} label="Type" />
          </div>
        </div>
      </div>

      <div className={`overflow-x-auto transition-opacity ${loading && data ? "opacity-60" : ""}`}>
        <table className="w-full min-w-[860px] text-left text-[13.5px]">
          <thead>
            <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
              <th className="w-14 py-3 pl-6 font-medium">#</th>
              <th className="py-3 font-medium">Indicator</th>
              <th className="py-3 font-medium">Source</th>
              <th className="py-3 font-medium">First seen</th>
              <th className="py-3 font-medium">Location</th>
              <th className="py-3 font-medium">Status</th>
              <th className="py-3 pr-6 text-right font-medium">Score</th>
            </tr>
          </thead>
          <tbody>
            {!data && !error &&
              Array.from({ length: SIZE }, (_, i) => (
                <tr key={i} className="border-b border-line/70">
                  <td colSpan={7} className="px-6 py-3.5">
                    <Skeleton className="h-6 w-full" />
                  </td>
                </tr>
              ))}
            {data?.items.map((r, i) => {
              const Icon = ICON[r.type] ?? Shapes;
              const [label, pill] = PILL[r.status] ?? PILL.active;
              return (
                <tr key={r.id} className="group border-b border-line/70 transition-colors odd:bg-white/[0.012] hover:bg-accent/[0.06]">
                  <td className="py-3.5 pl-6 text-ink-faint tabular-nums">{(page - 1) * SIZE + i + 1}</td>
                  <td className="py-3.5 pr-4">
                    <a href={`/ui/indicators/${r.id}`} className="flex items-center gap-3">
                      <span className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-accent/10 text-accent-soft ring-1 ring-accent/20" title={r.typeLabel}>
                        <Icon className="h-4 w-4" />
                      </span>
                      <span className="min-w-0">
                        <Ioc value={r.value.length > 72 ? `${r.value.slice(0, 70)}…` : r.value} />
                        <span className="block text-[12px] text-ink-faint group-hover:text-accent-soft">
                          {r.typeLabel} · {r.tlp}
                        </span>
                      </span>
                    </a>
                  </td>
                  <td className="py-3.5 text-ink-muted">{r.sources.join(", ") || "–"}</td>
                  <td className="whitespace-nowrap py-3.5 text-ink-muted">{DATE.format(new Date(r.firstSeen))}</td>
                  <td className="py-3.5 text-ink-muted">{r.country ?? "–"}</td>
                  <td className="py-3.5">
                    <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[12px] font-medium ring-1 ${pill}`}>
                      <span className="h-1.5 w-1.5 rounded-full bg-current" />
                      {label}
                    </span>
                  </td>
                  <td className="py-3.5 pr-6">
                    <Score n={r.score} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {error && !data && <Failed error={error} onRetry={reload} />}
        {data && !data.items.length && <Empty>Nothing matches these filters.</Empty>}
      </div>

      <footer className="flex items-center justify-between gap-3 px-6 py-4 text-[13px] text-ink-muted">
        <span>
          {data ? (
            <>
              Showing <b className="text-ink">{data.total ? (page - 1) * SIZE + 1 : 0}</b>–<b className="text-ink">{Math.min(data.total, page * SIZE)}</b> of{" "}
              <b className="text-ink">{data.total.toLocaleString()}</b>
            </>
          ) : (
            "Loading…"
          )}
        </span>
        <div className="flex items-center gap-1.5">
          <button className="btn-ghost h-8 w-8 !px-0 disabled:opacity-40" disabled={page === 1} onClick={() => setPage(page - 1)} aria-label="Previous page">
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span className="px-2 tabular-nums">
            {page.toLocaleString()} / {pages.toLocaleString()}
          </span>
          <button className="btn-ghost h-8 w-8 !px-0 disabled:opacity-40" disabled={page >= pages} onClick={() => setPage(page + 1)} aria-label="Next page">
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </footer>
    </Card>
  );
}
