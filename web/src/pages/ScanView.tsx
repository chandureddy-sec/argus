import { CheckCircle2, Download, Globe2, Loader2, Save, Search, Server } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ModePill, SevPill } from "../components/recon";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, Segmented, token } from "../components/ui";
import { post, useApi, useText, type GeoPoint, type Me, type Report } from "../lib/api";
import { dateTime } from "../lib/format";
import { usePage } from "../lib/page";

const TABS = ["Hosts", "Findings", "Ports", "Map", "Sources", "Downloads"] as const;
type Tab = (typeof TABS)[number];
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

function Stat({ label, value, hint }: { label: string; value: number | string; hint?: string }) {
  return (
    <div className="py-3 sm:px-5 sm:first:pl-0">
      <p className="label">{label}</p>
      <p className="mt-1.5 text-[26px] font-bold leading-none tabular-nums">{typeof value === "number" ? value.toLocaleString() : value}</p>
      {hint && <p className="mt-1.5 text-[12px] text-ink-faint">{hint}</p>}
    </div>
  );
}

function Hosts({ rep }: { rep: Report }) {
  const [q, setQ] = useState("");
  const [live, setLive] = useState(false);
  const nodes = rep.attack_surface_graph?.nodes ?? [];
  const shown = nodes.filter((n) => (!live || n.is_alive) && `${n.hostname} ${(n.resolved_ips ?? []).join(" ")} ${n.organization ?? ""}`.toLowerCase().includes(q.trim().toLowerCase()));
  if (!nodes.length) return <Empty>This scan has no host list (it may have been active-only).</Empty>;
  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3 px-5 sm:px-6">
        <label className="relative w-full max-w-xs">
          <span className="sr-only">Filter hosts</span>
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
          <input value={q} onChange={(e) => setQ(e.target.value)} className="ctl h-8 w-full pl-9 text-[13px]" placeholder="Filter by host, IP or network owner" />
        </label>
        <label className="flex cursor-pointer items-center gap-2 text-[13px] text-ink-muted">
          <input type="checkbox" className="h-4 w-4 accent-[#1F6BFF]" checked={live} onChange={(e) => setLive(e.target.checked)} /> Live only
        </label>
        <span className="ml-auto text-[12.5px] text-ink-faint">
          {shown.length.toLocaleString()} of {nodes.length.toLocaleString()}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[860px] text-left text-[13.5px]">
          <thead>
            <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
              <th className="py-3 pl-6 font-medium">Host</th>
              <th className="py-3 font-medium">Addresses</th>
              <th className="py-3 font-medium">Network</th>
              <th className="py-3 font-medium">Country</th>
              <th className="py-3 font-medium">Seen by</th>
              <th className="py-3 pr-6 font-medium">State</th>
            </tr>
          </thead>
          <tbody>
            {shown.slice(0, 500).map((n) => (
              <tr key={n.hostname} className="border-b border-line/70 odd:bg-white/[0.012] hover:bg-accent/[0.06]">
                <td className="py-3 pl-6 font-mono text-[13px]">{n.hostname}</td>
                <td className="py-3 font-mono text-[12.5px] text-ink-muted">{(n.resolved_ips ?? []).slice(0, 3).join(", ") || "–"}{(n.resolved_ips?.length ?? 0) > 3 && ` +${n.resolved_ips!.length - 3}`}</td>
                <td className="py-3 text-ink-muted">
                  {n.organization || n.isp || "–"}
                  {n.asn && <span className="ml-1.5 text-[12px] text-ink-faint">{n.asn.startsWith("AS") ? n.asn : `AS${n.asn}`}</span>}
                  {n.cloud_provider && <span className="ml-2 rounded bg-accent/10 px-1.5 text-[11.5px] text-accent-soft">{n.cloud_provider}</span>}
                </td>
                <td className="py-3 text-ink-muted">{n.country || "–"}</td>
                <td className="whitespace-nowrap py-3 text-ink-muted" title={n.sources.join(", ")}>
                  {n.sources.length} source{n.sources.length === 1 ? "" : "s"}
                </td>
                <td className="py-3 pr-6">
                  <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[12px] font-medium ring-1 ${n.is_alive ? "bg-up/10 text-up ring-up/20" : "bg-ink-faint/15 text-ink-muted ring-line"}`}>
                    <span className="h-1.5 w-1.5 rounded-full bg-current" />
                    {n.is_alive ? "Live" : "No answer"}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {shown.length > 500 && <p className="px-6 py-3 text-[12.5px] text-ink-faint">Showing the first 500; download the CSV for all of them.</p>}
      </div>
    </>
  );
}

function Findings({ rep }: { rep: Report }) {
  const all = [...(rep.active_recon?.findings ?? [])].sort((a, b) => SEV_ORDER.indexOf(a.severity.toLowerCase()) - SEV_ORDER.indexOf(b.severity.toLowerCase()));
  if (!rep.active_recon) return <Empty>Findings come from active checks; this was a passive scan.</Empty>;
  if (!all.length) return <Empty>No findings: the active checks passed.</Empty>;
  return (
    <ul className="divide-y divide-line/70 border-t border-line">
      {all.map((f, i) => (
        <li key={i} className="px-5 py-4 sm:px-6">
          <details className="group">
            <summary className="flex cursor-pointer list-none items-start gap-3">
              <SevPill sev={f.severity} />
              <span className="min-w-0 flex-1">
                <span className="block font-medium text-ink group-open:text-accent-soft">{f.title}</span>
                <span className="block text-[12.5px] text-ink-faint">
                  {f.category} · <span className="font-mono">{f.target}</span>
                </span>
              </span>
            </summary>
            <p className="mt-3 pl-[74px] text-[13.5px] text-ink-muted">{f.description}</p>
            {f.evidence && <pre className="ml-[74px] mt-2 overflow-x-auto rounded-ctl border border-line bg-bg p-3 font-mono text-[12px] text-ink-muted">{f.evidence}</pre>}
          </details>
        </li>
      ))}
    </ul>
  );
}

function Ports({ rep }: { rep: Report }) {
  const ports = (rep.active_recon?.open_ports ?? []).filter((p) => p.state === "open");
  if (!rep.active_recon) return <Empty>Ports come from active checks; this was a passive scan.</Empty>;
  if (!ports.length) return <Empty>No open ports were found (or the port scan was off).</Empty>;
  return (
    <div className="grid gap-3 px-5 pb-6 sm:grid-cols-2 sm:px-6 lg:grid-cols-3">
      {ports.map((p) => (
        <div key={`${p.port}/${p.protocol}`} className="rounded-ctl border border-line bg-card-2/40 p-3.5">
          <p className="flex items-baseline gap-2">
            <span className="text-[20px] font-bold tabular-nums">{p.port}</span>
            <span className="text-[12px] uppercase text-ink-faint">{p.protocol}</span>
            <span className="ml-auto text-[13px] text-accent-soft">{p.service || "unknown"}</span>
          </p>
          {p.banner && <p className="mt-1.5 truncate font-mono text-[12px] text-ink-muted" title={p.banner}>{p.banner}</p>}
        </div>
      ))}
    </div>
  );
}

function MapTab({ refId }: { refId: string }) {
  const geo = useApi<{ points: GeoPoint[]; missing: number }>("recon/report/geo", { ref: refId });
  const land = useText("recon/worldmap");
  const [hover, setHover] = useState<GeoPoint>();
  if (geo.error && !geo.data) return <Failed error={geo.error} onRetry={geo.reload} />;
  if (!geo.data) return <Skeleton className="mx-6 mb-6 h-[360px]" />;
  const pts = geo.data.points;
  const max = Math.max(1, ...pts.map((p) => p.ips.length));
  return (
    <div className="px-5 pb-6 sm:px-6">
      <div className="relative overflow-hidden rounded-card border border-line bg-bg">
        <svg viewBox="0 0 1000 500" className="block w-full" role="img" aria-label={`Map of ${pts.length} locations`}>
          {land && <path d={land} fill={token("card-2")} stroke={token("line")} strokeWidth={0.6} />}
          {pts.map((p) => {
            const r = 4 + 10 * Math.sqrt(p.ips.length / max);
            return (
              <g key={`${p.x},${p.y}`} onMouseEnter={() => setHover(p)} onMouseLeave={() => setHover(undefined)} className="cursor-pointer">
                <circle cx={p.x} cy={p.y} r={r * 2.2} fill={token(p.exposed ? "down" : "accent", 0.12)} />
                <circle cx={p.x} cy={p.y} r={r} fill={token(p.exposed ? "down" : "accent", 0.85)} stroke="#fff" strokeOpacity={0.6} strokeWidth={1} />
              </g>
            );
          })}
        </svg>
        {hover && (
          <div className="pointer-events-none absolute left-3 top-3 max-w-xs rounded-ctl border border-line bg-card-2/95 px-3 py-2 text-[13px] shadow-xl">
            <p className="font-semibold">{hover.place}</p>
            <p className="text-ink-muted">
              {hover.ips.length} IP{hover.ips.length === 1 ? "" : "s"} · {hover.hosts} host{hover.hosts === 1 ? "" : "s"}
              {hover.exposed ? <span className="text-down"> · {hover.exposed} with open ports</span> : null}
            </p>
            {hover.providers?.length ? <p className="text-[12px] text-ink-faint">{hover.providers.join(", ")}</p> : null}
          </div>
        )}
      </div>
      <p className="mt-2 text-[12.5px] text-ink-faint">
        {pts.length} location{pts.length === 1 ? "" : "s"}
        {geo.data.missing ? ` · ${geo.data.missing} IPs without a location` : ""} · red: IPs with open ports in internet scan data
      </p>
    </div>
  );
}

function Sources({ rep }: { rep: Report }) {
  const runs = rep.passive_intel?.sources ?? [];
  if (!runs.length) return <Empty>No passive sources ran in this scan.</Empty>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left text-[13.5px]">
        <thead>
          <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
            <th className="py-3 pl-6 font-medium">Source</th>
            <th className="py-3 font-medium">Used for</th>
            <th className="py-3 text-right font-medium">Results</th>
            <th className="py-3 text-right font-medium">Took</th>
            <th className="py-3 pl-6 pr-6 font-medium">Outcome</th>
          </tr>
        </thead>
        <tbody>
          {runs.map((s) => (
            <tr key={s.name} className="border-b border-line/70 odd:bg-white/[0.012]">
              <td className="py-3 pl-6 font-medium">{s.name}</td>
              <td className="py-3 text-ink-muted">{s.purpose}</td>
              <td className="py-3 text-right tabular-nums">{s.results.toLocaleString()}</td>
              <td className="py-3 text-right tabular-nums text-ink-muted">{(s.duration_ms / 1000).toFixed(1)} s</td>
              <td className="py-3 pl-6 pr-6">
                <span className={s.status === "ok" ? "text-up" : s.status === "skipped" ? "text-ink-muted" : "text-warn"} title={s.error}>
                  {s.status}
                  {s.error && <span className="ml-2 text-[12px] text-ink-faint">{s.error.slice(0, 60)}</span>}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Downloads({ refId }: { refId: string }) {
  const items: [string, string, string][] = [
    ["json", "Full report (JSON)", "everything the engine found, for scripts and archives"],
    ["html", "Report (HTML)", "the styled ReconX report, to share or print"],
    ["md", "Report (Markdown)", "for tickets and wikis"],
    ["csv", "Attack surface (CSV)", "one row per host, for spreadsheets"],
    ["graphml", "Infrastructure graph (GraphML)", "for Gephi, yEd or Maltego"],
  ];
  return (
    <ul className="grid gap-3 px-5 pb-6 sm:grid-cols-2 sm:px-6">
      {items.map(([fmt, title, hint]) => (
        <li key={fmt}>
          <a href={`/app/api/recon/report/download?ref=${encodeURIComponent(refId)}&format=${fmt}`} className="flex items-center gap-3 rounded-ctl border border-line bg-card-2/40 p-3.5 hover:border-accent/50">
            <Download className="h-5 w-5 text-accent-soft" />
            <span>
              <span className="block text-[14px] font-medium">{title}</span>
              <span className="block text-[12.5px] text-ink-muted">{hint}</span>
            </span>
          </a>
        </li>
      ))}
    </ul>
  );
}

export default function ScanView({ me }: { me?: Me }) {
  const { ref = "" } = useParams();
  const nav = useNavigate();
  const { data: rep, error, reload } = useApi<Report>("recon/report", { ref });
  const target = rep?.target?.value ?? "Scan";
  usePage("Attack surface", "Scans", target);
  const [tab, setTab] = useState<Tab>("Hosts");
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string>();
  const unsaved = ref.startsWith("job:");

  const stats = useMemo(() => {
    const nodes = rep?.attack_surface_graph?.nodes ?? [];
    const ips = new Set(nodes.flatMap((n) => n.resolved_ips ?? []));
    const findings = rep?.active_recon?.findings ?? [];
    const high = findings.filter((f) => ["critical", "high"].includes(f.severity.toLowerCase())).length;
    return {
      hosts: rep?.attack_surface_graph?.total_assets ?? nodes.length,
      live: rep?.attack_surface_graph?.live_assets ?? nodes.filter((n) => n.is_alive).length,
      ips: ips.size,
      ports: (rep?.active_recon?.open_ports ?? []).filter((p) => p.state === "open").length,
      findings: findings.length,
      high,
    };
  }, [rep]);
  const mode = rep ? (rep.active_recon || rep.web_map ? (rep.attack_surface_graph ? "both" : "active") : "passive") : "passive";

  const save = async () => {
    setSaving(true);
    setSaveError(undefined);
    try {
      const res = await post<{ file: string }>(`recon/jobs/${ref.slice(4)}/save`);
      nav(`/scans/view/${encodeURIComponent(res.file)}`, { replace: true });
    } catch (e) {
      setSaveError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  if (error && !rep) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Failed error={error} onRetry={reload} />
          {unsaved && <p className="text-center text-[13px] text-ink-muted">Unsaved scans are lost when the engine restarts.</p>}
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-center gap-4">
            <span className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-accent/10 text-accent-soft ring-1 ring-accent/20">
              <Globe2 className="h-6 w-6" />
            </span>
            <div>
              {rep ? <h1 className="font-mono text-[22px] font-bold tracking-tight">{target}</h1> : <Skeleton className="h-7 w-48" />}
              <p className="mt-1 flex flex-wrap items-center gap-2 text-[13px] text-ink-muted">
                {rep && dateTime(rep.timestamp)} <ModePill mode={mode} />
                {unsaved ? <span className="text-warn">Not saved</span> : <span className="inline-flex items-center gap-1 text-up"><CheckCircle2 className="h-3.5 w-3.5" /> Saved</span>}
              </p>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {unsaved && me?.role !== "viewer" && (
              <button className="btn-primary" onClick={save} disabled={saving}>
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save and add to assets
              </button>
            )}
            <Link to={`/scans/compare?b=${encodeURIComponent(ref)}`} className="btn-ghost">
              Compare…
            </Link>
          </div>
        </div>
        {saveError && <p className="mb-3 text-[13px] text-down">{saveError}</p>}
        <div className="grid grid-cols-2 divide-line border-t border-line sm:grid-cols-3 lg:grid-cols-5 lg:divide-x">
          <Stat label="Hosts found" value={stats.hosts} />
          <Stat label="Live hosts" value={stats.live} />
          <Stat label="IP addresses" value={stats.ips} />
          <Stat label="Open ports" value={rep?.active_recon ? stats.ports : "–"} hint={rep?.active_recon ? undefined : "active scans only"} />
          <Stat label="Findings" value={rep?.active_recon ? stats.findings : "–"} hint={!rep?.active_recon ? "active scans only" : stats.high ? `${stats.high} high or critical` : undefined} />
        </div>
      </Card>

      <Card className="!p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 p-5 sm:p-6">
          <h2 className="flex items-center gap-2 text-[15px] font-semibold">
            <Server className="h-4 w-4 text-accent-soft" /> Results
          </h2>
          <Segmented value={tab} options={TABS} onChange={setTab} label="Result views" />
        </div>
        {!rep ? (
          <Skeleton className="mx-6 mb-6 h-64" />
        ) : tab === "Hosts" ? (
          <Hosts rep={rep} />
        ) : tab === "Findings" ? (
          <Findings rep={rep} />
        ) : tab === "Ports" ? (
          <Ports rep={rep} />
        ) : tab === "Map" ? (
          <MapTab refId={ref} />
        ) : tab === "Sources" ? (
          <Sources rep={rep} />
        ) : (
          <Downloads refId={ref} />
        )}
      </Card>
    </div>
  );
}
