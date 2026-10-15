import { ChevronLeft, ChevronRight, Search } from "lucide-react";
import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Ioc, Score, StatusPill, TlpTag } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Select } from "../components/ui";
import { useDebounced, useV1, type Indicator, type SourceOut } from "../lib/api";
import { ago, date } from "../lib/format";
import { TYPE_LABEL } from "../lib/ioc";
import { usePage } from "../lib/page";

const SIZE = 25;
const TYPES: [string, string][] = [["All types", ""], ["IPv4 addresses", "ipv4-addr"], ["IP ranges", "ipv4-net"], ["Domains", "domain-name"], ["URLs", "url"], ["SHA-256", "file-sha256"], ["MD5", "file-md5"], ["CVEs", "vulnerability"]];
const STATUSES: [string, string][] = [["All statuses", ""], ["Active", "active"], ["Expired", "expired"], ["Not malicious", "false_positive"], ["Revoked", "revoked"]];
const SORTS: [string, string][] = [["Newest first", "recent"], ["Highest score", "priority"]];

export default function Indicators() {
  usePage("Threat intel", "Indicators");
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const search = useDebounced(q);
  const type = params.get("type") ?? "";
  const status = params.get("status") ?? "";
  const source = params.get("source") ?? "";
  const sort = params.get("sort") ?? "recent";
  const page = Number(params.get("page") ?? "1");
  const set = (k: string, v: string) =>
    setParams((p) => {
      if (v) p.set(k, v);
      else p.delete(k);
      if (k !== "page") p.delete("page");
      return p;
    });
  const sources = useV1<SourceOut[]>("sources");
  const { data, error, loading, reload } = useV1<{ items: Indicator[]; total: number }>("indicators", {
    q: search.trim().length >= 2 ? search.trim() : undefined,
    type: type || undefined,
    status: status || undefined,
    source: source || undefined,
    sort,
    limit: SIZE,
    offset: (page - 1) * SIZE,
  });
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / SIZE));
  const feedNames = (sources.data ?? []).filter((s) => s.kind !== "enricher");

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card className="!p-0">
        <div className="p-5 pb-0 sm:p-6 sm:pb-0">
          <CardHead title="Indicators" sub={data ? `${data.total.toLocaleString()} matching, within your clearance` : "Everything your feeds and analysts reported"} />
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
                placeholder="Value, label or malware (defanged is fine)"
              />
            </label>
            <Select value={TYPES.find(([, v]) => v === type)?.[0] ?? "All types"} options={TYPES.map(([l]) => l)} onChange={(l) => set("type", TYPES.find(([x]) => x === l)?.[1] ?? "")} label="Type" />
            <Select value={STATUSES.find(([, v]) => v === status)?.[0] ?? "All statuses"} options={STATUSES.map(([l]) => l)} onChange={(l) => set("status", STATUSES.find(([x]) => x === l)?.[1] ?? "")} label="Status" />
            <Select
              value={feedNames.find((s) => s.name === source)?.title ?? "All sources"}
              options={["All sources", ...feedNames.map((s) => s.title)]}
              onChange={(l) => set("source", feedNames.find((s) => s.title === l)?.name ?? "")}
              label="Source"
            />
            <Select value={SORTS.find(([, v]) => v === sort)?.[0] ?? "Newest first"} options={SORTS.map(([l]) => l)} onChange={(l) => set("sort", SORTS.find(([x]) => x === l)?.[1] ?? "recent")} label="Sort" />
          </div>
        </div>
        <div className={`overflow-x-auto transition-opacity ${loading && data ? "opacity-60" : ""}`}>
          <table className="w-full min-w-[960px] text-left text-[13.5px]">
            <thead>
              <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                <th className="py-3 pl-6 font-medium">Indicator</th>
                <th className="py-3 font-medium">Sources</th>
                <th className="py-3 font-medium">Labels</th>
                <th className="py-3 font-medium">First seen</th>
                <th className="py-3 font-medium">Last seen</th>
                <th className="py-3 font-medium">Status</th>
                <th className="py-3 pr-6 text-right font-medium">Score</th>
              </tr>
            </thead>
            <tbody>
              {!data && !error &&
                Array.from({ length: 10 }, (_, i) => (
                  <tr key={i} className="border-b border-line/70">
                    <td colSpan={7} className="px-6 py-3">
                      <Skeleton className="h-6 w-full" />
                    </td>
                  </tr>
                ))}
              {data?.items.map((r) => (
                <tr key={r.id} className="group border-b border-line/70 odd:bg-zebra hover:bg-row-hover">
                  <td className="max-w-[420px] py-3 pl-6 pr-4">
                    <Link to={`/indicators/${r.id}`} className="block">
                      <Ioc value={r.defanged.length > 90 ? `${r.defanged.slice(0, 88)}…` : r.defanged} className="text-[13px] text-ink group-hover:text-accent-soft" />
                      <span className="mt-0.5 flex items-center gap-2 text-[12px] text-ink-faint">
                        {TYPE_LABEL[r.type] ?? r.type} <TlpTag tlp={r.tlp} />
                        {r.analyst_verdict && <span className={r.analyst_verdict === "tp" ? "text-down" : "text-up"}>{r.analyst_verdict === "tp" ? "analyst: malicious" : "analyst: not malicious"}</span>}
                      </span>
                    </Link>
                  </td>
                  <td className="py-3 text-ink-muted">{r.sources.join(", ") || "analyst"}</td>
                  <td className="max-w-[220px] py-3">
                    <span className="flex flex-wrap gap-1">
                      {r.labels.slice(0, 3).map((l) => (
                        <span key={l} className="rounded bg-chip px-1.5 py-px text-[11.5px] text-chip-ink ring-1 ring-line">
                          {l}
                        </span>
                      ))}
                      {r.labels.length > 3 && <span className="text-[11.5px] text-ink-faint">+{r.labels.length - 3}</span>}
                    </span>
                  </td>
                  <td className="whitespace-nowrap py-3 text-ink-muted">{date(r.first_seen)}</td>
                  <td className="whitespace-nowrap py-3 text-ink-muted">{ago(r.last_seen)}</td>
                  <td className="py-3">
                    <StatusPill status={r.status} />
                  </td>
                  <td className="py-3 pr-6 text-right">
                    <Score n={r.priority_score} />
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
            <span className="px-2 tabular-nums">
              {page.toLocaleString()} / {pages.toLocaleString()}
            </span>
            <button className="btn-ghost h-8 w-8 !px-0" disabled={page >= pages} onClick={() => set("page", String(page + 1))} aria-label="Next page">
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </footer>
      </Card>
    </div>
  );
}
