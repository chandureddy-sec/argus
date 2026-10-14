import { ArrowLeftRight, CheckCircle2, CircleDashed, Plus, Radar, Search } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { EngineBanner, FindingCounts, ModePill } from "../components/recon";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { useApi, type Me, type ScanRow } from "../lib/api";
import { ago, dateTime, scanRef } from "../lib/format";
import { usePage } from "../lib/page";

export default function Scans({ me }: { me?: Me }) {
  usePage("Attack surface", "Scans");
  const { data, error, reload } = useApi<ScanRow[]>("recon/scans");
  const [q, setQ] = useState("");
  const [picked, setPicked] = useState<string[]>([]);
  const nav = useNavigate();
  const rows = useMemo(() => (data ?? []).filter((r) => r.target.includes(q.trim().toLowerCase())), [data, q]);
  const pickedRows = (data ?? []).filter((r) => picked.includes(scanRef(r)));
  const sameTarget = pickedRows.length === 2 && pickedRows[0].target === pickedRows[1].target;
  const toggle = (ref: string) => setPicked((p) => (p.includes(ref) ? p.filter((x) => x !== ref) : [...p.slice(-1), ref]));
  const compare = () => {
    const [newer, older] = [...pickedRows].sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    nav(`/scans/compare?a=${encodeURIComponent(scanRef(older))}&b=${encodeURIComponent(scanRef(newer))}`);
  };
  const targets = new Set((data ?? []).map((r) => r.target)).size;

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <EngineBanner />
      <Card className="!p-0">
        <div className="p-5 pb-0 sm:p-6 sm:pb-0">
          <CardHead
            title="Scans"
            sub={data ? `${data.length} scans of ${targets} target${targets === 1 ? "" : "s"} · saved scans feed your assets` : "Your ReconX scans"}
          >
            <button className="btn-ghost h-9" disabled={!sameTarget} onClick={compare} title={sameTarget ? "Compare the two ticked scans" : "Tick two scans of the same target"}>
              <ArrowLeftRight className="h-4 w-4" /> Compare
            </button>
            {me?.role !== "viewer" && (
              <Link to="/scans/new" className="btn-primary">
                <Plus className="h-4 w-4" /> New scan
              </Link>
            )}
          </CardHead>
          <label className="relative mb-4 block max-w-xs">
            <span className="sr-only">Filter by target</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} className="ctl h-8 w-full pl-9 text-[13px]" placeholder="Filter by target" />
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-[13.5px]">
            <thead>
              <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                <th className="w-12 py-3 pl-6" aria-label="Pick to compare" />
                <th className="py-3 font-medium">Target</th>
                <th className="py-3 font-medium">When</th>
                <th className="py-3 font-medium">Mode</th>
                <th className="py-3 text-right font-medium">Subdomains</th>
                <th className="py-3 text-right font-medium">Live hosts</th>
                <th className="py-3 pl-6 font-medium">Findings</th>
                <th className="py-3 pr-6 font-medium">Kept</th>
              </tr>
            </thead>
            <tbody>
              {!data && !error &&
                Array.from({ length: 5 }, (_, i) => (
                  <tr key={i} className="border-b border-line/70">
                    <td colSpan={8} className="px-6 py-3.5">
                      <Skeleton className="h-6 w-full" />
                    </td>
                  </tr>
                ))}
              {rows.map((r) => {
                const ref = scanRef(r);
                return (
                  <tr key={ref} className="group border-b border-line/70 transition-colors odd:bg-white/[0.012] hover:bg-accent/[0.06]">
                    <td className="py-3.5 pl-6">
                      <input type="checkbox" className="h-4 w-4 accent-[#1F6BFF]" checked={picked.includes(ref)} onChange={() => toggle(ref)} aria-label={`Pick ${r.target} ${dateTime(r.timestamp)} to compare`} />
                    </td>
                    <td className="py-3.5">
                      <Link to={`/scans/view/${encodeURIComponent(ref)}`} className="flex items-center gap-3">
                        <span className="inline-flex h-8 w-8 items-center justify-center rounded-full bg-accent/10 text-accent-soft ring-1 ring-accent/20">
                          <Radar className="h-4 w-4" />
                        </span>
                        <span className="font-medium text-ink group-hover:text-accent-soft">{r.target}</span>
                      </Link>
                    </td>
                    <td className="whitespace-nowrap py-3.5 text-ink-muted" title={dateTime(r.timestamp)}>
                      {ago(r.timestamp)}
                    </td>
                    <td className="py-3.5">
                      <ModePill mode={r.mode} />
                    </td>
                    <td className="py-3.5 text-right tabular-nums">{r.subdomains.toLocaleString()}</td>
                    <td className="py-3.5 text-right tabular-nums">{r.live_hosts.toLocaleString()}</td>
                    <td className="py-3.5 pl-6">{r.has_active ? <FindingCounts high={r.high} medium={r.medium} low={r.low} /> : <span className="text-ink-faint">passive only</span>}</td>
                    <td className="py-3.5 pr-6">
                      {r.file ? (
                        <span className="inline-flex items-center gap-1.5 text-[12.5px] text-up" title={r.imported ? "Saved; its hosts and IPs are in Assets" : "Saved"}>
                          <CheckCircle2 className="h-4 w-4" /> {r.imported ? "Saved · in assets" : "Saved"}
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[12.5px] text-warn" title="Kept only until the engine restarts: open it and press Save">
                          <CircleDashed className="h-4 w-4" /> Not saved
                        </span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {error && !data && <Failed error={error} onRetry={reload} />}
          {data && !rows.length && (
            <Empty>
              {data.length ? (
                "No scan matches this filter."
              ) : (
                <>
                  No scans yet.{" "}
                  {me?.role !== "viewer" && (
                    <Link to="/scans/new" className="text-accent-soft hover:underline">
                      Run the first one
                    </Link>
                  )}
                </>
              )}
            </Empty>
          )}
        </div>
      </Card>
    </div>
  );
}
