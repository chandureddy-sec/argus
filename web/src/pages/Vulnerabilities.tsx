import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Select } from "../components/ui";
import { useDebounced, useV1 } from "../lib/api";
import { date } from "../lib/format";
import { usePage } from "../lib/page";
import { plain } from "../lib/text";

export interface VulnRow {
  cve_id: string;
  description: string;
  published: string | null;
  cvss_score: number | null;
  cvss_severity: string | null;
  kev: boolean;
  kev_date_added: string | null;
  epss: number | null;
  epss_percentile: number | null;
  patch_priority: string | null;
  patch_score: number | null;
}

export const PRIO_TONE: Record<string, string> = { P1: "bg-down/15 text-down", P2: "bg-warn/15 text-warn", P3: "bg-info/10 text-info-soft", P4: "bg-chip text-chip-ink" };
const SIZE = 25;
const SORTS: [string, string][] = [["Patch priority", "patch"], ["Exploit likelihood (EPSS)", "epss"], ["Severity (CVSS)", "cvss"], ["Added to KEV", "kev_date"], ["Published", "published"]];
const PRIOS = ["All priorities", "P1", "P2", "P3", "P4"];

export function cvssTone(n: number | null): string {
  if (n == null) return "text-ink-faint";
  return n >= 9 ? "text-down" : n >= 7 ? "text-warn" : n >= 4 ? "text-accent-soft" : "text-ink-muted";
}

export default function Vulnerabilities() {
  usePage("Threat intel", "Vulnerabilities");
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const search = useDebounced(q);
  const kev = params.get("kev") === "true";
  const prio = params.get("patch_priority") ?? "";
  const sort = params.get("sort") ?? "patch";
  const page = Number(params.get("page") ?? "1");
  const set = (k: string, v: string) =>
    setParams((p) => {
      if (v) p.set(k, v);
      else p.delete(k);
      if (k !== "page") p.delete("page");
      return p;
    });
  const { data, error, loading, reload } = useV1<{ items: VulnRow[]; total: number }>("vulnerabilities", {
    q: search.trim().length >= 2 ? search.trim() : undefined,
    kev: kev ? "true" : undefined,
    patch_priority: prio || undefined,
    sort,
    limit: SIZE,
    offset: (page - 1) * SIZE,
  });
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / SIZE));

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card className="!p-0">
        <div className="p-5 pb-0 sm:p-6 sm:pb-0">
          <CardHead title="Vulnerabilities" sub={data ? `${data.total.toLocaleString()} CVEs: known exploited (KEV), in your stack, or seen in feeds` : "CVEs that matter to you"} />
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <label className="relative w-full sm:w-72">
              <span className="sr-only">Search</span>
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
              <input
                value={q}
                onChange={(e) => {
                  setQ(e.target.value);
                  set("q", e.target.value);
                }}
                className="ctl h-8 w-full pl-9 text-[13px]"
                placeholder="CVE id or words from the description"
              />
            </label>
            <label className="flex items-center gap-2 text-[13px] text-ink-muted">
              <input type="checkbox" className="h-4 w-4 accent-down" checked={kev} onChange={(e) => set("kev", e.target.checked ? "true" : "")} /> Known exploited only
            </label>
            <Select value={prio || "All priorities"} options={PRIOS} onChange={(v) => set("patch_priority", v === "All priorities" ? "" : v)} label="Patch priority" />
            <Select value={SORTS.find(([, v]) => v === sort)?.[0] ?? SORTS[0][0]} options={SORTS.map(([l]) => l)} onChange={(l) => set("sort", SORTS.find(([x]) => x === l)?.[1] ?? "patch")} label="Sort" />
          </div>
        </div>
        <div className={`overflow-x-auto transition-opacity ${loading && data ? "opacity-60" : ""}`}>
          <table className="w-full min-w-[900px] text-left text-[13.5px]">
            <thead>
              <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                <th className="py-3 pl-6 font-medium">CVE</th>
                <th className="py-3 font-medium">What it is</th>
                <th className="py-3 text-right font-medium">CVSS</th>
                <th className="py-3 text-right font-medium">EPSS</th>
                <th className="py-3 pl-5 font-medium">Exploited</th>
                <th className="py-3 pr-6 text-right font-medium">Priority</th>
              </tr>
            </thead>
            <tbody>
              {!data && !error &&
                Array.from({ length: 10 }, (_, i) => (
                  <tr key={i}>
                    <td colSpan={6} className="px-6 py-3">
                      <Skeleton className="h-6" />
                    </td>
                  </tr>
                ))}
              {data?.items.map((v) => (
                <tr key={v.cve_id} className="group border-b border-line/70 odd:bg-zebra hover:bg-row-hover">
                  <td className="whitespace-nowrap py-3 pl-6">
                    <Link to={`/vulnerabilities/${v.cve_id}`} className="font-mono text-[13px] group-hover:text-accent-soft">
                      {v.cve_id}
                    </Link>
                    <span className="block text-[12px] text-ink-faint">{date(v.published)}</span>
                  </td>
                  <td className="max-w-[520px] py-3 pr-4 text-[13px] text-ink-muted">
                    <span className="line-clamp-2">{plain(v.description) || "No description yet."}</span>
                  </td>
                  <td className={`py-3 text-right font-semibold tabular-nums ${cvssTone(v.cvss_score)}`}>{v.cvss_score?.toFixed(1) ?? "–"}</td>
                  <td className="py-3 text-right tabular-nums text-ink-muted" title={v.epss_percentile != null ? `${Math.round(v.epss_percentile * 100)}th percentile` : undefined}>
                    {v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "–"}
                  </td>
                  <td className="py-3 pl-5">{v.kev ? <span className="rounded bg-down/15 px-1.5 py-0.5 text-[12px] font-semibold text-down">KEV · {date(v.kev_date_added)}</span> : <span className="text-ink-faint">–</span>}</td>
                  <td className="py-3 pr-6 text-right">
                    {v.patch_priority ? <span className={`rounded px-2 py-0.5 text-[12px] font-bold ${PRIO_TONE[v.patch_priority]}`}>{v.patch_priority}</span> : <span className="text-ink-faint">–</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {error && !data && <Failed error={error} onRetry={reload} />}
          {data && !data.items.length && <Empty>Nothing matches these filters.</Empty>}
        </div>
        <footer className="flex items-center justify-between gap-3 px-6 py-4 text-[13px] text-ink-muted">
          <span>{data ? `${data.total ? ((page - 1) * SIZE + 1).toLocaleString() : 0}–${Math.min(data.total, page * SIZE).toLocaleString()} of ${data.total.toLocaleString()}` : "Loading…"}</span>
          <div className="flex items-center gap-1.5">
            <button className="btn-ghost h-8 w-8 !px-0" disabled={page <= 1} onClick={() => set("page", String(page - 1))} aria-label="Previous page">
              <ChevronLeft className="h-4 w-4" />
            </button>
            <span className="px-2 tabular-nums">{page} / {pages}</span>
            <button className="btn-ghost h-8 w-8 !px-0" disabled={page >= pages} onClick={() => set("page", String(page + 1))} aria-label="Next page">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </footer>
      </Card>
    </div>
  );
}
