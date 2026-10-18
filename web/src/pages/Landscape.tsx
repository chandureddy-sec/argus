import { AlertOctagon, Briefcase, Bug, CircleCheck, Database, ExternalLink, Flame } from "lucide-react";
import { Link } from "react-router-dom";
import CalendarCard from "../components/CalendarCard";
import { Ioc, Score, VerdictPill } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import ThreatMap from "../components/ThreatMap";
import { Card, CardHead, compact } from "../components/ui";
import { useApi } from "../lib/api";
import { ago, date } from "../lib/format";
import { usePage } from "../lib/page";

interface Vuln {
  cve: string;
  name: string;
  product: string;
  added: string | null;
  due: string | null;
  ransomware: boolean;
  epss: number | null;
  cvss: number | null;
  priority: string | null;
}

interface LandscapeData {
  kpis: { label: string; value: number; sub: string; href: string }[];
  queue: { id: number; type: string; value: string; score: number; verdict: string; action: string; source: string; why: string; last_seen: string | null }[];
  families: { name: string; count: number; href: string }[];
  techniques: { label: string; count: number; href: string }[];
  tactics: { name: string; count: number }[];
  kevLatest: Vuln[];
  kevStack: Vuln[];
  patch: { priority: string; count: number }[];
  geo: Record<string, number>;
  geoLocated: number;
  pirs: { id: string; question: string; n: number; unit: string; state: string }[];
  activity: { at: string; tone: string; kind: string; title: string; detail: string; href: string }[];
  feedRates: { name: string; health: string; ok: number; runs: number; pct: number }[];
}

function Bars({ rows, tone = "bg-accent" }: { rows: { label: string; count: number; href?: string }[]; tone?: string }) {
  const max = Math.max(1, ...rows.map((r) => r.count));
  if (!rows.length) return <Empty>Nothing yet.</Empty>;
  return (
    <ul className="space-y-3">
      {rows.map((r) => (
        <li key={r.label}>
          <div className="flex items-center justify-between gap-3 text-[13px]">
            {r.href ? (
              <Link to={r.href} className="truncate hover:text-accent-soft">
                {r.label}
              </Link>
            ) : (
              <span className="truncate">{r.label}</span>
            )}
            <span className="tabular-nums text-ink-muted">{r.count.toLocaleString()}</span>
          </div>
          <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line">
            <div className={`h-full rounded-full ${tone}`} style={{ width: `${(100 * r.count) / max}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

const ACT_ICON: Record<string, typeof Flame> = { "Case opened": Briefcase, "Case closed": CircleCheck, "Feed failed": AlertOctagon, Collected: Database, "Added to KEV": Bug };
const ACT_TONE: Record<string, string> = { pink: "text-accent-soft bg-tint", lime: "text-up bg-up/10", red: "text-down bg-down/10", cyan: "text-accent-soft bg-tint", amber: "text-warn bg-warn/10" };
const PRIO: Record<string, string> = { P1: "bg-down/15 text-down", P2: "bg-warn/15 text-warn", P3: "bg-info/10 text-info-soft", P4: "bg-chip text-chip-ink" };

function VulnRow({ v }: { v: Vuln }) {
  return (
    <li className="flex items-start gap-3 py-2.5">
      <span className={`mt-0.5 shrink-0 rounded px-1.5 text-[11.5px] font-bold ${PRIO[v.priority ?? "P4"] ?? PRIO.P4}`}>{v.priority ?? "–"}</span>
      <div className="min-w-0 flex-1">
        <Link to={`/vulnerabilities/${v.cve}`} className="font-mono text-[13px] hover:text-accent-soft">
          {v.cve}
        </Link>
        <p className="truncate text-[12.5px] text-ink-muted">{v.name || v.product}</p>
      </div>
      <span className="shrink-0 text-right text-[12px] text-ink-faint">
        {date(v.added)}
        {v.ransomware && <span className="block text-down">ransomware</span>}
      </span>
    </li>
  );
}

export default function Landscape() {
  usePage("Home", "Threat landscape");
  const { data: d, error, reload } = useApi<LandscapeData>("landscape");
  if (error && !d) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Failed error={error} onRetry={reload} />
        </Card>
      </div>
    );
  }
  const countries = Object.entries(d?.geo ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        {(d?.kpis ?? Array.from({ length: 5 }, () => null)).map((k, i) =>
          k ? (
            <Link key={k.label} to={k.href} className="card p-4 transition-colors hover:border-accent/40">
              <p className="label">{k.label}</p>
              <p className="mt-1.5 text-[26px] font-bold tabular-nums" title={k.value.toLocaleString()}>{compact(k.value)}</p>
              <p className="text-[12px] text-ink-faint">{k.sub}</p>
            </Link>
          ) : (
            <Skeleton key={i} className="h-[104px] !rounded-card" />
          ),
        )}
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,8fr)_minmax(0,4fr)]">
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Look at these first" sub="Highest-scoring active indicators, at most two per feed and type so one bulk feed can't fill the list">
              <Link to="/indicators?sort=priority&status=active" className="btn-ghost h-8 text-[13px]">All →</Link>
            </CardHead>
          </div>
          {!d ? (
            <Skeleton className="mx-6 mb-6 h-48" />
          ) : !d.queue.length ? (
            <Empty>Nothing scored yet.</Empty>
          ) : (
            <ul className="divide-y divide-line/70 border-t border-line">
              {d.queue.map((q) => (
                <li key={q.id}>
                  <Link to={`/indicators/${q.id}`} className="grid grid-cols-[1fr_auto] items-center gap-x-4 gap-y-1 px-5 py-3 hover:bg-row-hover sm:grid-cols-[minmax(0,1fr)_auto_auto] sm:px-6">
                    <span className="min-w-0">
                      <Ioc value={q.value.length > 80 ? `${q.value.slice(0, 78)}…` : q.value} className="text-[13px]" />
                      <span className="block truncate text-[12px] text-ink-faint">
                        {q.type} · {q.source} · {q.why}
                      </span>
                    </span>
                    <span className="hidden sm:block">
                      <VerdictPill verdict={q.verdict} />
                    </span>
                    <Score n={q.score} />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHead title="Intelligence requirements" sub="What you asked to watch, and how much matches now" />
          {!d ? (
            <Skeleton className="h-40" />
          ) : !d.pirs.length ? (
            <Empty>No requirements set (config/pirs.yaml).</Empty>
          ) : (
            <ul className="space-y-3">
              {d.pirs.map((p) => (
                <li key={p.id} className="rounded-ctl border border-line bg-card-2/40 p-3">
                  <p className="flex items-center justify-between gap-2 text-[12px]">
                    <span className="font-mono text-ink-faint">{p.id}</span>
                    <span className={`rounded-full px-2 py-0.5 font-semibold ${p.state === "action" ? "bg-down/15 text-down" : p.state === "active" ? "bg-warn/15 text-warn" : "bg-chip text-chip-ink"}`}>{p.state === "action" ? "act now" : p.state}</span>
                  </p>
                  <p className="mt-1 text-[13px] text-ink">{p.question}</p>
                  <p className="mt-1 text-[12px] text-ink-muted">
                    <b className="text-ink">{p.n.toLocaleString()}</b> {p.unit}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
        <Card>
          <CardHead title="Malware families" sub="Named by the indicators your feeds report">
            <Link to="/attack" className="btn-ghost h-8 text-[13px]">ATT&CK →</Link>
          </CardHead>
          {d ? <Bars rows={d.families.map((f) => ({ label: f.name, count: f.count, href: f.href }))} tone="bg-down/80" /> : <Skeleton className="h-40" />}
        </Card>
        <Card>
          <CardHead title="Techniques they use" sub="Most-shared ATT&CK techniques of those families" />
          {d ? <Bars rows={d.techniques.map((t) => ({ label: t.label, count: t.count, href: t.href }))} /> : <Skeleton className="h-40" />}
        </Card>
        <Card>
          <CardHead title="Where the infrastructure is" sub={d ? `${d.geoLocated.toLocaleString()} located IPs` : "Located indicator IPs"} />
          {d ? <Bars rows={countries.map(([c, n]) => ({ label: c, count: n }))} tone="bg-teal" /> : <Skeleton className="h-40" />}
        </Card>
      </div>

      <ThreatMap />

      <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
        <Card>
          <CardHead title="Newly exploited (KEV)" sub="CISA Known Exploited Vulnerabilities, latest first">
            <Link to="/vulnerabilities?kev=true&sort=kev_date" className="btn-ghost h-8 text-[13px]">All →</Link>
          </CardHead>
          {d ? d.kevLatest.length ? <ul className="divide-y divide-line/70">{d.kevLatest.map((v) => <VulnRow key={v.cve} v={v} />)}</ul> : <Empty>No KEV data yet.</Empty> : <Skeleton className="h-40" />}
        </Card>
        <Card>
          <CardHead title="Exploited in your stack" sub="KEV entries matching your software (profile + what scans found)" />
          {d ? d.kevStack.length ? <ul className="divide-y divide-line/70">{d.kevStack.map((v) => <VulnRow key={v.cve} v={v} />)}</ul> : <Empty>None matches your stack. Scan your domains to fill it in.</Empty> : <Skeleton className="h-40" />}
        </Card>
        <Card>
          <CardHead title="Patch priority" sub="Every known CVE by how urgently to patch" />
          {d ? (
            <div className="grid grid-cols-2 gap-3">
              {d.patch.map((p) => (
                <Link key={p.priority} to={`/vulnerabilities?patch_priority=${p.priority}&sort=patch`} className="rounded-ctl border border-line bg-card-2/40 p-3 hover:border-accent/40">
                  <span className={`rounded px-1.5 text-[12px] font-bold ${PRIO[p.priority]}`}>{p.priority}</span>
                  <p className="mt-2 text-[22px] font-bold tabular-nums">{p.count.toLocaleString()}</p>
                  <p className="text-[11.5px] text-ink-faint">{{ P1: "patch now", P2: "this week", P3: "this month", P4: "routine" }[p.priority]}</p>
                </Link>
              ))}
            </div>
          ) : (
            <Skeleton className="h-40" />
          )}
        </Card>
      </div>

      <div className="grid gap-6 lg:grid-cols-2 xl:grid-cols-3">
        <div id="activity" className="scroll-mt-20"><Card>
          <CardHead title="This week" sub="Cases, feeds and new exploited CVEs, newest first" />
          {!d ? (
            <Skeleton className="h-40" />
          ) : !d.activity.length ? (
            <Empty>A quiet week.</Empty>
          ) : (
            <ol className="relative space-y-4 border-l border-line pl-5">
              {d.activity.map((a, i) => {
                const Icon = ACT_ICON[a.kind] ?? Flame;
                return (
                  <li key={i} className="relative">
                    <span className={`absolute -left-[33px] top-0 inline-flex h-6 w-6 items-center justify-center rounded-full ring-4 ring-card ${ACT_TONE[a.tone] ?? ACT_TONE.cyan}`}>
                      <Icon className="h-3.5 w-3.5" />
                    </span>
                    <p className="text-[12px] text-ink-faint">
                      {a.kind} · {ago(a.at)}
                    </p>
                    <Link to={a.href} className="text-[13.5px] font-medium hover:text-accent-soft">
                      {a.title}
                    </Link>
                    {a.detail && <p className="text-[12.5px] text-ink-muted">{a.detail}</p>}
                  </li>
                );
              })}
            </ol>
          )}
        </Card></div>
        <CalendarCard />
        <Card>
          <CardHead title="Feed reliability" sub="Share of pulls that worked in the last 7 days">
            <Link to="/feeds" className="btn-ghost h-8 text-[13px]">
              Catalog <ExternalLink className="h-3.5 w-3.5" />
            </Link>
          </CardHead>
          {d ? (
            <ul className="space-y-3">
              {d.feedRates.map((f) => (
                <li key={f.name}>
                  <div className="flex items-center justify-between text-[13px]">
                    <Link to={`/feeds/${f.name}`} className="hover:text-accent-soft">{f.name}</Link>
                    <span className="tabular-nums text-ink-muted">{Math.round(f.pct)}% · {f.runs} pull{f.runs === 1 ? "" : "s"}</span>
                  </div>
                  <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line">
                    <div className={`h-full rounded-full ${f.pct >= 90 ? "bg-up" : f.pct >= 50 ? "bg-warn" : "bg-down"}`} style={{ width: `${f.pct}%` }} />
                  </div>
                </li>
              ))}
              {!d.feedRates.length && <Empty>No pulls in the last 7 days.</Empty>}
            </ul>
          ) : (
            <Skeleton className="h-40" />
          )}
        </Card>
      </div>
    </div>
  );
}
