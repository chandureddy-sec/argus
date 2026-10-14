import { AlertTriangle, Radar, Search } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Ioc, Score, StatusPill } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { useDebounced, useV1, type AssetOut } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { defang } from "../lib/ioc";
import { usePage } from "../lib/page";

const TABS = ["Assets", "Software", "Imports"] as const;
const KINDS = ["All", "Domains", "Hosts", "IPs"] as const;
const KIND_KEY: Record<string, string | undefined> = { All: undefined, Domains: "domain", Hosts: "host", IPs: "ip" };

interface Product {
  vendor: string;
  product: string;
  versions: string[];
  assets: number;
  cves: number;
  kev_cves: number;
}

interface ImportRow {
  id: number;
  source: string;
  target: string;
  scanned_at: string | null;
  imported_at: string;
  imported_by: string;
  counts: Record<string, number>;
}

function AssetList() {
  const [kind, setKind] = useState<(typeof KINDS)[number]>("All");
  const [flagged, setFlagged] = useState(false);
  const [q, setQ] = useState("");
  const search = useDebounced(q);
  const { data, error, reload } = useV1<{ items: AssetOut[]; total: number }>("assets", {
    kind: KIND_KEY[kind],
    flagged: flagged ? "true" : undefined,
    q: search.trim().length >= 2 ? search.trim() : undefined,
    limit: 200,
  });
  return (
    <>
      <div className="flex flex-wrap items-center gap-3 px-5 pb-4 sm:px-6">
        <Segmented value={kind} options={KINDS} onChange={setKind} label="Kind" />
        <label className="flex items-center gap-2 text-[13px] text-ink-muted">
          <input type="checkbox" className="h-4 w-4 accent-[#F43F5E]" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} /> Flagged by threat intel only
        </label>
        <label className="relative ml-auto w-full sm:w-64">
          <span className="sr-only">Filter</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
          <input value={q} onChange={(e) => setQ(e.target.value)} className="ctl h-8 w-full pl-9 text-[13px]" placeholder="Host, IP or target" />
        </label>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-left text-[13.5px]">
          <thead>
            <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
              <th className="py-3 pl-6 font-medium">Asset</th>
              <th className="py-3 font-medium">Of target</th>
              <th className="py-3 font-medium">Software</th>
              <th className="py-3 font-medium">Last seen</th>
              <th className="py-3 pr-6 font-medium">Threat intel</th>
            </tr>
          </thead>
          <tbody>
            {!data && !error &&
              Array.from({ length: 6 }, (_, i) => (
                <tr key={i}>
                  <td colSpan={5} className="px-6 py-3">
                    <Skeleton className="h-6" />
                  </td>
                </tr>
              ))}
            {data?.items.map((a) => (
              <tr key={a.id} className={`border-b border-line/70 odd:bg-white/[0.012] ${a.indicator?.status === "active" ? "bg-down/[0.04]" : ""}`}>
                <td className="py-3 pl-6">
                  <Ioc value={defang(a.value)} className="text-[13px]" />
                  <span className="block text-[12px] text-ink-faint">{a.kind} · from {a.origin}</span>
                </td>
                <td className="py-3 font-mono text-[12.5px] text-ink-muted">{defang(a.target)}</td>
                <td className="max-w-[260px] py-3 text-[12.5px] text-ink-muted">
                  {a.products.length ? a.products.slice(0, 3).map((p) => p.split(":").slice(3, 6).filter((x) => x && x !== "*").join(" ")).join(", ") : "–"}
                  {a.products.length > 3 && ` +${a.products.length - 3}`}
                </td>
                <td className="whitespace-nowrap py-3 text-ink-muted" title={dateTime(a.last_seen)}>
                  {ago(a.last_seen)}
                </td>
                <td className="py-3 pr-6">
                  {a.indicator ? (
                    <Link to={`/indicators/${a.indicator.indicator_id}`} className="inline-flex items-center gap-2">
                      {a.indicator.status === "active" && <AlertTriangle className="h-4 w-4 text-down" />}
                      <StatusPill status={a.indicator.status} />
                      <Score n={a.indicator.priority_score} />
                      <span className="text-[12px] text-ink-faint">{a.indicator.sources.join(", ")}</span>
                    </Link>
                  ) : (
                    <span className="text-[12.5px] text-ink-faint">not listed by any feed</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {error && !data && <Failed error={error} onRetry={reload} />}
        {data && !data.items.length && (
          <Empty>
            No assets {flagged ? "flagged" : "yet"}.{" "}
            {!flagged && (
              <Link to="/scans/new" className="text-accent-soft hover:underline">
                Scan a domain you own
              </Link>
            )}
          </Empty>
        )}
      </div>
    </>
  );
}

function Software() {
  const { data, error, reload } = useV1<Product[]>("assets/products");
  if (error && !data) return <Failed error={error} onRetry={reload} />;
  if (!data) return <Skeleton className="mx-6 mb-6 h-32" />;
  if (!data.length) return <Empty>No software seen yet: scans with internet-scan data (Shodan InternetDB) fill this.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-[13.5px]">
        <thead>
          <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
            <th className="py-3 pl-6 font-medium">Product</th>
            <th className="py-3 font-medium">Versions</th>
            <th className="py-3 text-right font-medium">Assets</th>
            <th className="py-3 text-right font-medium">Known CVEs</th>
            <th className="py-3 pr-6 text-right font-medium">Exploited (KEV)</th>
          </tr>
        </thead>
        <tbody>
          {data.map((p) => (
            <tr key={`${p.vendor}/${p.product}`} className="border-b border-line/70 odd:bg-white/[0.012]">
              <td className="py-3 pl-6">
                <span className="font-medium">{p.product.replace(/_/g, " ")}</span>
                <span className="block text-[12px] text-ink-faint">{p.vendor}</span>
              </td>
              <td className="py-3 font-mono text-[12.5px] text-ink-muted">{p.versions.join(", ") || "–"}</td>
              <td className="py-3 text-right tabular-nums">{p.assets}</td>
              <td className="py-3 text-right tabular-nums">{p.cves}</td>
              <td className={`py-3 pr-6 text-right font-semibold tabular-nums ${p.kev_cves ? "text-down" : "text-ink-faint"}`}>{p.kev_cves}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Imports() {
  const { data, error, reload } = useV1<ImportRow[]>("assets/imports", { limit: 50 });
  if (error && !data) return <Failed error={error} onRetry={reload} />;
  if (!data) return <Skeleton className="mx-6 mb-6 h-32" />;
  if (!data.length) return <Empty>No scans imported yet.</Empty>;
  return (
    <ul className="divide-y divide-line/70 border-t border-line">
      {data.map((i) => (
        <li key={i.id} className="flex flex-wrap items-center gap-x-5 gap-y-1 px-5 py-3 text-[13.5px] sm:px-6">
          <Radar className="h-4 w-4 text-accent-soft" />
          <span className="font-mono">{defang(i.target)}</span>
          <span className="text-ink-muted">scanned {ago(i.scanned_at)}, imported {ago(i.imported_at)} by {i.imported_by}</span>
          <span className="ml-auto text-[12.5px] text-ink-faint">
            {Object.entries(i.counts)
              .filter(([, v]) => typeof v === "number")
              .map(([k, v]) => `${v} ${k.replace(/_/g, " ")}`)
              .join(" · ")}
          </span>
        </li>
      ))}
    </ul>
  );
}

export default function Assets() {
  usePage("Home", "Assets");
  const [tab, setTab] = useState<(typeof TABS)[number]>("Assets");
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card className="!p-0">
        <div className="p-5 pb-4 sm:p-6 sm:pb-4">
          <CardHead title="Your assets" sub="Hosts, IPs and domains from saved ReconX scans. Threat intel watches them: a feed listing one is the strongest signal there is, and they are never blocked.">
            <Segmented value={tab} options={TABS} onChange={setTab} label="View" />
          </CardHead>
        </div>
        {tab === "Assets" ? <AssetList /> : tab === "Software" ? <Software /> : <Imports />}
      </Card>
    </div>
  );
}
