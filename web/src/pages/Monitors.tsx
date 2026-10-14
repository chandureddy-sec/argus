import { BellRing, Loader2, Pause, Play, Plus, Send, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { EngineBanner, SevPill } from "../components/recon";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { post, useApi, type Alert, type Me, type Monitor } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { usePage } from "../lib/page";

const EVERY: [string, string][] = [["6h", "Every 6 hours"], ["12h", "Every 12 hours"], ["1d", "Daily"], ["7d", "Weekly"]];

function StatusPill({ m }: { m: Monitor }) {
  if (!m.enabled) return <span className="rounded-full bg-ink-faint/15 px-2.5 py-0.5 text-[12px] text-ink-muted ring-1 ring-line">Paused</span>;
  if (m.last_status === "running") return <span className="inline-flex items-center gap-1 rounded-full bg-accent/10 px-2.5 py-0.5 text-[12px] text-accent-soft ring-1 ring-accent/20"><Loader2 className="h-3 w-3 animate-spin" /> Running</span>;
  if (m.last_status === "error") return <span className="rounded-full bg-down/10 px-2.5 py-0.5 text-[12px] text-down ring-1 ring-down/20" title={m.last_error}>Last run failed</span>;
  return <span className="rounded-full bg-up/10 px-2.5 py-0.5 text-[12px] text-up ring-1 ring-up/20">Watching</span>;
}

export default function Monitors({ me }: { me?: Me }) {
  usePage("Attack surface", "Monitors");
  const list = useApi<{ monitors: Monitor[]; scheduler: boolean }>("recon/monitors");
  const alerts = useApi<Alert[]>("recon/alerts");
  const admin = me?.role === "admin";
  const [target, setTarget] = useState("");
  const [every, setEvery] = useState("1d");
  const [webhook, setWebhook] = useState("");
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();

  const act = async (id: string, action: string) => {
    if (action === "delete" && !window.confirm("Delete this monitor? Its past alerts stay.")) return;
    setBusy(`${id}:${action}`);
    setError(undefined);
    try {
      await post(`recon/monitors/${id}/${action}`);
      list.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("add");
    setError(undefined);
    try {
      await post("recon/monitors", { target: target.trim().toLowerCase(), every, webhook: webhook.trim() });
      setTarget("");
      setWebhook("");
      list.reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  const monitors = list.data?.monitors ?? [];
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <EngineBanner />
      <div className="grid gap-6 xl:grid-cols-[minmax(0,8fr)_minmax(0,4fr)]">
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Monitors" sub="Passive scans on a schedule. Each run is compared with the last one and raises alerts on what changed; saved runs flow into your assets." />
          </div>
          {list.error && !list.data ? (
            <Failed error={list.error} onRetry={list.reload} />
          ) : !list.data ? (
            <Skeleton className="mx-6 mb-6 h-40" />
          ) : !monitors.length ? (
            <Empty>No monitors yet.{admin ? " Add one on the right." : " An admin can add them."}</Empty>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[760px] text-left text-[13.5px]">
                <thead>
                  <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                    <th className="py-3 pl-6 font-medium">Target</th>
                    <th className="py-3 font-medium">Every</th>
                    <th className="py-3 font-medium">Last run</th>
                    <th className="py-3 font-medium">Next run</th>
                    <th className="py-3 font-medium">State</th>
                    <th className="py-3 pr-6 text-right font-medium">{admin ? "Actions" : "Runs"}</th>
                  </tr>
                </thead>
                <tbody>
                  {monitors.map((m) => (
                    <tr key={m.id} className="border-b border-line/70 odd:bg-white/[0.012]">
                      <td className="py-3 pl-6">
                        <span className="font-mono">{m.target}</span>
                        {m.webhook_kind && <span className="ml-2 rounded bg-accent/10 px-1.5 text-[11.5px] text-accent-soft">{m.webhook_kind}</span>}
                      </td>
                      <td className="py-3 text-ink-muted">{m.every}</td>
                      <td className="py-3 text-ink-muted" title={dateTime(m.last_run)}>
                        {m.last_file ? (
                          <Link to={`/scans/view/${encodeURIComponent(m.last_file)}`} className="hover:text-accent-soft">
                            {ago(m.last_run)}
                          </Link>
                        ) : (
                          ago(m.last_run)
                        )}
                        {m.last_alerts > 0 && <span className="ml-2 text-[12px] text-warn">{m.last_alerts} alert{m.last_alerts === 1 ? "" : "s"}</span>}
                      </td>
                      <td className="py-3 text-ink-muted" title={dateTime(m.next_run)}>
                        {m.enabled ? ago(m.next_run) : "–"}
                      </td>
                      <td className="py-3">
                        <StatusPill m={m} />
                      </td>
                      <td className="py-3 pr-6">
                        {admin ? (
                          <div className="flex justify-end gap-1.5">
                            <button className="btn-ghost h-8 w-8 !px-0" title="Run now" aria-label={`Run ${m.target} now`} disabled={!!busy || m.last_status === "running"} onClick={() => act(m.id, "run")}>
                              {busy === `${m.id}:run` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                            </button>
                            <button className="btn-ghost h-8 w-8 !px-0" title={m.enabled ? "Pause" : "Resume"} aria-label={m.enabled ? "Pause" : "Resume"} disabled={!!busy} onClick={() => act(m.id, m.enabled ? "pause" : "resume")}>
                              {m.enabled ? <Pause className="h-4 w-4" /> : <BellRing className="h-4 w-4" />}
                            </button>
                            {m.webhook && (
                              <button className="btn-ghost h-8 w-8 !px-0" title="Send a test alert" aria-label="Send a test alert" disabled={!!busy} onClick={() => act(m.id, "test")}>
                                <Send className="h-4 w-4" />
                              </button>
                            )}
                            <button className="btn-ghost h-8 w-8 !px-0 hover:!text-down" title="Delete" aria-label={`Delete monitor ${m.target}`} disabled={!!busy} onClick={() => act(m.id, "delete")}>
                              <Trash2 className="h-4 w-4" />
                            </button>
                          </div>
                        ) : (
                          <span className="block text-right tabular-nums text-ink-muted">{m.runs}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {error && <p className="px-6 py-3 text-[13px] text-down">{error}</p>}
          {list.data && !list.data.scheduler && <p className="px-6 py-3 text-[12.5px] text-warn">The engine's scheduler is off: monitors only run when you press Run.</p>}
        </Card>

        <Card>
          <CardHead title="Add a monitor" sub={admin ? "Passive only: it never contacts the target." : "Adding monitors needs the admin role."} />
          <form onSubmit={add} className="space-y-4">
            <fieldset disabled={!admin || busy === "add"} className="space-y-4">
              <label className="block">
                <span className="label mb-1.5 block">Domain</span>
                <input value={target} onChange={(e) => setTarget(e.target.value)} className="ctl w-full font-mono" placeholder="example.com" required />
              </label>
              <label className="block">
                <span className="label mb-1.5 block">How often</span>
                <select value={every} onChange={(e) => setEvery(e.target.value)} className="ctl w-full">
                  {EVERY.map(([v, l]) => (
                    <option key={v} value={v}>
                      {l}
                    </option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="label mb-1.5 block">Alert webhook (optional)</span>
                <input value={webhook} onChange={(e) => setWebhook(e.target.value)} className="ctl w-full" placeholder="https://hooks.slack.com/…" type="url" pattern="https://.*" />
                <span className="mt-1 block text-[12px] text-ink-faint">Slack, Discord or any https endpoint. Stored by the engine; shown masked.</span>
              </label>
            </fieldset>
            <button type="submit" className="btn-primary w-full" disabled={!admin || !target.trim() || busy === "add"}>
              {busy === "add" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add monitor
            </button>
          </form>
        </Card>
      </div>

      <Card className="!p-0">
        <div className="p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Recent alerts" sub="What monitors noticed: new subdomains, IP changes, expiring certificates, threat-intel hits and more" />
        </div>
        {alerts.error && !alerts.data ? (
          <Failed error={alerts.error} onRetry={alerts.reload} />
        ) : !alerts.data ? (
          <Skeleton className="mx-6 mb-6 h-24" />
        ) : !alerts.data.length ? (
          <Empty>No alerts yet.</Empty>
        ) : (
          <ul className="divide-y divide-line/70 border-t border-line">
            {alerts.data.slice(0, 100).map((a) => (
              <li key={a.id} className="flex flex-wrap items-start gap-3 px-5 py-3.5 sm:px-6">
                <SevPill sev={a.severity} />
                <div className="min-w-0 flex-1">
                  <p className="text-[14px] text-ink">{a.title}</p>
                  <p className="text-[12.5px] text-ink-faint">
                    <span className="font-mono">{a.target}</span> · {a.rule.replace(/_/g, " ")} · {ago(a.time)}
                  </p>
                  {a.items?.length ? (
                    <p className="mt-1 truncate font-mono text-[12px] text-ink-muted">
                      {a.items.slice(0, 5).join(", ")}
                      {(a.more ?? 0) > 0 && ` +${a.more} more`}
                    </p>
                  ) : null}
                </div>
                {a.scan_file && (
                  <Link to={`/scans/view/${encodeURIComponent(a.scan_file)}`} className="text-[12.5px] text-accent-soft hover:underline">
                    Open scan
                  </Link>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
