import { Search } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Ioc, Score, StatusPill } from "../components/intel";
import { SevPill } from "../components/recon";
import { SavedViews } from "../components/SavedViews";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { useApi } from "../lib/api";
import { TYPE_LABEL } from "../lib/ioc";
import { usePage } from "../lib/page";
import { plain } from "../lib/text";
import { PRIO_TONE } from "./Vulnerabilities";

interface Results {
  q: string;
  open: string | null;
  indicators: { id: number; type: string; value: string; score: number | null; status: string; labels: string[] }[];
  indicatorsTotal: number;
  entities: { ref: string; name: string; type: string; id: string | null }[];
  cves: { cve: string; kev: boolean; priority: string | null; cvss: number | null; description: string }[];
  cases: { id: number; title: string; status: string; severity: string }[];
}

export default function SearchPage() {
  usePage("Search");
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const all = params.get("all") === "true";
  const [text, setText] = useState(q);
  const nav = useNavigate();
  const { data, error, loading, reload } = useApi<Results>("search", { q, all: all ? "true" : undefined });
  useEffect(() => setText(q), [q]);
  useEffect(() => {
    if (data?.open) nav(data.open, { replace: true }); // an exact hit opens its page
  }, [data?.open, nav]);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setParams({ q: text.trim() });
  };
  const empty = data && !data.indicators.length && !data.entities.length && !data.cves.length && !data.cases.length;

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Search everything" sub="An indicator, CVE, ATT&CK id or malware name opens its page; anything else lists matches. tag:qakbot searches labels." />
        <form onSubmit={submit} className="flex gap-2">
          <label className="relative flex-1">
            <span className="sr-only">Search</span>
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input value={text} onChange={(e) => setText(e.target.value)} className="ctl h-11 w-full pl-10 text-[14.5px]" placeholder="185.220.101.34, CVE-2024-3400, T1059, Emotet, tag:phishing" autoFocus maxLength={300} />
          </label>
          <button className="btn-primary h-11 px-5" disabled={!text.trim()}>Search</button>
        </form>
        {q && !all && data && !data.open && (
          <p className="mt-2 text-[12.5px] text-ink-faint">
            No exact match: showing everything that contains "{q}".
          </p>
        )}
        <SavedViews />
      </Card>

      {!q ? null : error && !data ? (
        <Card><Failed error={error} onRetry={reload} /></Card>
      ) : !data || loading || data.open ? (
        <Skeleton className="h-40" />
      ) : empty ? (
        <Card><Empty>Nothing matches "{q}".</Empty></Card>
      ) : (
        <div className="grid gap-6 xl:grid-cols-2">
          {data.indicators.length > 0 && (
            <Card className="!p-0 xl:col-span-2">
              <div className="p-5 pb-3 sm:p-6 sm:pb-3">
                <CardHead title={`Indicators (${data.indicatorsTotal.toLocaleString()})`} sub={data.indicatorsTotal > data.indicators.length ? "The 25 highest-scoring" : undefined}>
                  <Link to={`/indicators?q=${encodeURIComponent(q.replace(/^tag:/i, ""))}`} className="btn-ghost h-8 text-[13px]">Open in Indicators →</Link>
                </CardHead>
              </div>
              <ul className="divide-y divide-line/70 border-t border-line">
                {data.indicators.map((i) => (
                  <li key={i.id}>
                    <Link to={`/indicators/${i.id}`} className="flex items-center gap-4 px-5 py-2.5 hover:bg-row-hover sm:px-6">
                      <span className="min-w-0 flex-1">
                        <Ioc value={i.value} className="text-[13px]" />
                        <span className="block text-[12px] text-ink-faint">{TYPE_LABEL[i.type] ?? i.type} · {i.labels.join(", ")}</span>
                      </span>
                      <StatusPill status={i.status} />
                      <Score n={i.score} />
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
          {data.entities.length > 0 && (
            <Card className="!p-0">
              <div className="p-5 pb-3 sm:p-6 sm:pb-3"><CardHead title="Malware, actors, techniques" /></div>
              <ul className="divide-y divide-line/70 border-t border-line">
                {data.entities.map((e) => (
                  <li key={e.ref}>
                    <Link to={`/entities/${encodeURIComponent(e.ref)}`} className="flex items-center justify-between gap-3 px-5 py-2.5 text-[13.5px] hover:bg-row-hover sm:px-6">
                      <span>{e.name}</span>
                      <span className="text-[12px] text-ink-faint">{e.id ?? ""} · {e.type}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
          {data.cves.length > 0 && (
            <Card className="!p-0">
              <div className="p-5 pb-3 sm:p-6 sm:pb-3"><CardHead title="Vulnerabilities" /></div>
              <ul className="divide-y divide-line/70 border-t border-line">
                {data.cves.map((v) => (
                  <li key={v.cve}>
                    <Link to={`/vulnerabilities/${v.cve}`} className="block px-5 py-2.5 hover:bg-row-hover sm:px-6">
                      <span className="flex items-center gap-2">
                        <span className="font-mono text-[13px]">{v.cve}</span>
                        {v.priority && <span className={`rounded px-1.5 text-[11px] font-bold ${PRIO_TONE[v.priority]}`}>{v.priority}</span>}
                        {v.kev && <span className="rounded bg-down/15 px-1.5 text-[11px] font-semibold text-down">KEV</span>}
                      </span>
                      <span className="block truncate text-[12.5px] text-ink-muted">{plain(v.description)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
          {data.cases.length > 0 && (
            <Card className="!p-0">
              <div className="p-5 pb-3 sm:p-6 sm:pb-3"><CardHead title="Cases" /></div>
              <ul className="divide-y divide-line/70 border-t border-line">
                {data.cases.map((c) => (
                  <li key={c.id}>
                    <Link to={`/cases/${c.id}`} className="flex items-center justify-between gap-3 px-5 py-2.5 text-[13.5px] hover:bg-row-hover sm:px-6">
                      <span><span className="text-ink-faint">#{c.id}</span> {c.title}</span>
                      <SevPill sev={c.severity} />
                    </Link>
                  </li>
                ))}
              </ul>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}
