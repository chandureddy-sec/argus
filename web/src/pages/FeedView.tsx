import { ExternalLink, Loader2, Pencil, RefreshCw, Trash2 } from "lucide-react";
import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Ioc, Score } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, reducedMotion, useToken } from "../components/ui";
import { send, useV1, type Me, type RunOut, type SourceOut } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { TYPE_LABEL } from "../lib/ioc";
import { usePage } from "../lib/page";
import { every, Health, Switch } from "./Feeds";

interface Contribution {
  total: number;
  by_status: Record<string, number>;
  by_type: Record<string, number>;
  corroborated: number;
  only_here: number;
  top: { id: number; type: string; value: string; priority_score: number | null; tlp: string }[];
}

const RUN_TONE: Record<string, string> = { success: "text-up", not_modified: "text-up", unchanged: "text-up", skipped: "text-ink-muted", too_soon: "text-ink-muted", partial: "text-warn", failed: "text-down" };
const RUN_LABEL: Record<string, string> = { not_modified: "no change (304)", unchanged: "same document", too_soon: "too soon" };

export default function FeedView({ me }: { me?: Me }) {
  const { name = "" } = useParams();
  const nav = useNavigate();
  const token = useToken();
  const sources = useV1<SourceOut[]>("sources");
  const s = sources.data?.find((x) => x.name === name);
  usePage("Platform", "Feed catalog", s?.title ?? name);
  const runs = useV1<RunOut[]>(`sources/${name}/runs`, { limit: 60 });
  const contrib = useV1<Contribution>(`sources/${name}/contribution`);
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const admin = me?.role === "admin";

  if (sources.data && !s) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Empty>No such source. <Link to="/feeds" className="text-accent-soft">Back to the catalog</Link></Empty>
        </Card>
      </div>
    );
  }

  const history = [...(runs.data ?? [])].reverse().map((r) => ({ when: new Date(r.started_at).toLocaleDateString("en", { month: "short", day: "2-digit" }), new: r.items_new, status: r.status }));
  const ok = (runs.data ?? []).filter((r) => ["success", "not_modified", "unchanged"].includes(r.status)).length;

  const pull = async () => {
    setBusy("pull");
    try {
      const r = await send<{ queued: boolean }>("POST", `/api/v1/sources/${name}/run`);
      setMsg(r.queued ? "Pull queued; refresh in a moment." : "Already queued.");
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const remove = async () => {
    if (!window.confirm(`Remove ${s?.title}? Its history and reports are deleted; indicators only it reported are revoked.`)) return;
    setBusy("rm");
    try {
      await send("DELETE", `/api/v1/sources/custom/${name}`);
      nav("/feeds");
    } catch (e) {
      setMsg((e as Error).message);
      setBusy(undefined);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        {!s ? (
          <Skeleton className="h-16" />
        ) : (
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <p className="mb-1.5 flex items-center gap-2 text-[12.5px] text-ink-muted">
                <Health s={s} /> {s.custom ? "Your feed" : s.kind === "enricher" ? "Lookup provider" : "Built-in source"} · {s.kind.replace(/-/g, " ")} · {s.kind === "enricher" ? "on demand" : `every ${every(s.interval_minutes)}`}
              </p>
              <h1 className="text-[22px] font-semibold">{s.title}</h1>
              {s.enabled && s.health !== "ok" && s.last_error && <p className="mt-2 max-w-3xl text-[13px] text-warn">Last pull failed: {s.last_error.slice(0, 300)}</p>}
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {admin && s.enabled && s.kind !== "enricher" && (
                <button className="btn-ghost h-9" onClick={pull} disabled={!!busy}>
                  {busy === "pull" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Pull now
                </button>
              )}
              {admin && s.custom && (
                <>
                  <Link to={`/feeds/${name}/edit`} className="btn-ghost h-9">
                    <Pencil className="h-4 w-4" /> Edit
                  </Link>
                  <button className="btn-ghost h-9 hover:!text-down" onClick={remove} disabled={!!busy}>
                    <Trash2 className="h-4 w-4" /> Remove
                  </button>
                </>
              )}
              <Switch s={s} admin={admin} onChange={sources.reload} />
            </div>
          </div>
        )}
        {msg && <p className="mt-3 text-[13px] text-ink-muted">{msg}</p>}
      </Card>

      {s?.kind !== "enricher" && (
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
          {[
            ["Indicators", contrib.data?.total, "reported, within your clearance"],
            ["Active", contrib.data?.by_status.active, `${contrib.data?.by_status.expired ?? 0} expired`],
            ["Only here", contrib.data?.only_here, "no other source reports them"],
            ["Corroborated", contrib.data?.corroborated, "also reported elsewhere"],
            ["Pulls OK", runs.data?.length ? `${Math.round((100 * ok) / runs.data.length)}%` : "–", `of the last ${runs.data?.length ?? 0}`],
          ].map(([l, v, h]) => (
            <div key={String(l)} className="card p-4">
              <p className="label">{l}</p>
              <p className="mt-1.5 text-[24px] font-bold tabular-nums">{v === undefined ? "–" : typeof v === "number" ? v.toLocaleString() : v}</p>
              <p className="text-[12px] text-ink-faint">{h}</p>
            </div>
          ))}
        </div>
      )}

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHead title="Where it comes from" />
          {!s ? (
            <Skeleton className="h-40" />
          ) : (
            <dl className="grid grid-cols-[150px_1fr] gap-x-4 gap-y-2.5 text-[13.5px]">
              <dt className="text-ink-faint">Reliability</dt>
              <dd>
                <b>{s.reliability}</b> <span className="text-ink-muted">{s.reliability_note}</span>
              </dd>
              {(s.feedback_tp > 0 || s.feedback_fp > 0) && (
                <>
                  <dt className="text-ink-faint">Analyst feedback</dt>
                  <dd className="text-ink-muted">{s.feedback_tp} confirmed · {s.feedback_fp} not malicious → weight ×{s.weight_factor.toFixed(2)}</dd>
                </>
              )}
              <dt className="text-ink-faint">Licence</dt>
              <dd>
                {s.license_url ? (
                  <a href={s.license_url} target="_blank" rel="noopener noreferrer" className="text-accent-soft hover:underline">
                    {s.license} <ExternalLink className="inline h-3 w-3" />
                  </a>
                ) : (
                  s.license
                )}
              </dd>
              <dt className="text-ink-faint">Use</dt>
              <dd className="text-ink-muted">{s.commercial_use ? "commercial use allowed" : "non-commercial only"} · {s.redistribution ? "may redistribute" : "never re-published"}</dd>
              {s.attribution && (
                <>
                  <dt className="text-ink-faint">Attribution</dt>
                  <dd className="text-ink-muted">{s.attribution}</dd>
                </>
              )}
              {s.requires_key && (
                <>
                  <dt className="text-ink-faint">API key</dt>
                  <dd className={s.key_configured ? "text-up" : "text-warn"}>{s.key_configured ? "configured" : "missing: pulls are skipped until it is set"}</dd>
                </>
              )}
              <dt className="text-ink-faint">Last success</dt>
              <dd className="text-ink-muted">{ago(s.last_success_at)}</dd>
              {s.enabled && s.next_run_at && s.kind !== "enricher" && (
                <>
                  <dt className="text-ink-faint">Next pull</dt>
                  <dd className="text-ink-muted">{ago(s.next_run_at)}</dd>
                </>
              )}
            </dl>
          )}
        </Card>
        <Card>
          <CardHead title="By indicator type" />
          {!contrib.data ? (
            <Skeleton className="h-40" />
          ) : !Object.keys(contrib.data.by_type).length ? (
            <Empty>Nothing reported yet.</Empty>
          ) : (
            <ul className="space-y-3">
              {Object.entries(contrib.data.by_type).map(([t, n]) => {
                const max = Math.max(...Object.values(contrib.data!.by_type));
                return (
                  <li key={t}>
                    <Link to={`/indicators?source=${name}&type=${t}`} className="flex items-center justify-between text-[13px] hover:text-accent-soft">
                      <span>{TYPE_LABEL[t] ?? t}</span>
                      <span className="tabular-nums text-ink-muted">{n.toLocaleString()}</span>
                    </Link>
                    <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line">
                      <div className="h-full rounded-full bg-accent" style={{ width: `${(100 * n) / max}%` }} />
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </Card>
      </div>

      {s?.kind !== "enricher" && (
        <Card className="!p-0">
          <div className="p-5 sm:p-6">
            <CardHead title="Pull history" sub="New indicators per pull, oldest left" />
            {runs.error && !runs.data ? (
              <Failed error={runs.error} onRetry={runs.reload} />
            ) : !runs.data ? (
              <Skeleton className="h-40" />
            ) : !runs.data.length ? (
              <Empty>Never pulled yet.</Empty>
            ) : (
              <div className="h-[180px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={history} margin={{ top: 4, right: 4, left: -18, bottom: 0 }}>
                    <CartesianGrid vertical={false} />
                    <XAxis dataKey="when" axisLine={false} tickLine={false} minTickGap={20} />
                    <YAxis axisLine={false} tickLine={false} width={48} allowDecimals={false} />
                    <Tooltip cursor={{ fill: token("accent", 0.06) }} contentStyle={{ background: token("card-2"), border: `1px solid ${token("line")}`, borderRadius: 10, fontSize: 13 }} />
                    <Bar dataKey="new" name="new indicators" fill={token("accent")} radius={[4, 4, 1, 1]} maxBarSize={16} isAnimationActive={!reducedMotion} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
          {runs.data?.length ? (
            <div className="overflow-x-auto border-t border-line">
              <table className="w-full min-w-[760px] text-left text-[13px]">
                <thead>
                  <tr className="border-b border-line bg-card-2/50 text-[11.5px] uppercase tracking-wide text-ink-muted">
                    <th className="py-2.5 pl-6 font-medium">When</th>
                    <th className="py-2.5 font-medium">Result</th>
                    <th className="py-2.5 text-right font-medium">Items</th>
                    <th className="py-2.5 text-right font-medium">New</th>
                    <th className="py-2.5 text-right font-medium">Updated</th>
                    <th className="py-2.5 text-right font-medium">Rejected</th>
                    <th className="py-2.5 pr-6 text-right font-medium">Allowlisted</th>
                  </tr>
                </thead>
                <tbody>
                  {runs.data.slice(0, 30).map((r, i) => (
                    <tr key={i} className="border-b border-line/60 odd:bg-zebra">
                      <td className="py-2.5 pl-6 text-ink-muted" title={dateTime(r.started_at)}>{ago(r.started_at)}</td>
                      <td className={`py-2.5 ${RUN_TONE[r.status] ?? "text-ink-muted"}`}>
                        {RUN_LABEL[r.status] ?? r.status}
                        {r.error && <span className="ml-2 text-[12px] text-ink-faint">{r.error.slice(0, 80)}</span>}
                      </td>
                      <td className="py-2.5 text-right tabular-nums">{r.items_total.toLocaleString()}</td>
                      <td className="py-2.5 text-right tabular-nums">{r.items_new.toLocaleString()}</td>
                      <td className="py-2.5 text-right tabular-nums">{r.items_updated.toLocaleString()}</td>
                      <td className="py-2.5 text-right tabular-nums">{r.items_rejected.toLocaleString()}</td>
                      <td className="py-2.5 pr-6 text-right tabular-nums">{r.items_allowlisted.toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </Card>
      )}

      {contrib.data?.top.length ? (
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Top active indicators from this source">
              <Link to={`/indicators?source=${name}&sort=priority`} className="btn-ghost h-8 text-[13px]">All →</Link>
            </CardHead>
          </div>
          <ul className="divide-y divide-line/70 border-t border-line">
            {contrib.data.top.map((t) => (
              <li key={t.id}>
                <Link to={`/indicators/${t.id}`} className="flex items-center gap-4 px-5 py-2.5 hover:bg-row-hover sm:px-6">
                  <Ioc value={t.value} className="min-w-0 flex-1 truncate text-[13px]" />
                  <span className="text-[12px] text-ink-faint">{TYPE_LABEL[t.type] ?? t.type}</span>
                  <Score n={t.priority_score} />
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}
