import { Loader2, MonitorCheck, ShieldAlert, ShieldX } from "lucide-react";
import { useState } from "react";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { post, useApi, type AedAlert, type AedEndpoint, type Me } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { usePage } from "../lib/page";

function StatusPill({ status }: { status: AedEndpoint["status"] }) {
  const map: Record<AedEndpoint["status"], [string, string]> = {
    online: ["bg-up/10 text-up ring-up/20", "Online"],
    pending: ["bg-ink-faint/15 text-ink-muted ring-line", "Pending"],
    stale: ["bg-warn/10 text-warn ring-warn/20", "Stale"],
    revoked: ["bg-down/10 text-down ring-down/20", "Revoked"],
  };
  const [cls, label] = map[status];
  return <span className={`rounded-full px-2.5 py-0.5 text-[12px] ring-1 ${cls}`}>{label}</span>;
}

function SevPill({ sev }: { sev?: string }) {
  const s = (sev ?? "").toLowerCase();
  const cls = s === "high" || s === "critical" ? "bg-down/10 text-down ring-down/20" : s === "medium" ? "bg-warn/10 text-warn ring-warn/20" : "bg-ink-faint/15 text-ink-muted ring-line";
  return <span className={`rounded-full px-2 py-0.5 text-[11.5px] ring-1 ${cls}`}>{sev ?? "info"}</span>;
}

/** Lab endpoint telemetry served by the AED gateway (admin proxy). Lab VMs only. */
export default function Endpoints({ me }: { me?: Me }) {
  usePage("Response", "Lab endpoints");
  const list = useApi<{ agents: AedEndpoint[] }>("aed/endpoints");
  const alerts = useApi<{ alerts: AedAlert[] }>("aed/alerts");
  const admin = me?.role === "admin";
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();

  const notConfigured = (list.error ?? "").startsWith("503");

  const revoke = async (id: string) => {
    if (!window.confirm(`Revoke ${id}? Its certificate stops authenticating; it must re-enroll.`)) return;
    setBusy(id);
    setError(undefined);
    try {
      await post(`aed/agents/${encodeURIComponent(id)}/revoke`);
      list.reload();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  const agents = list.data?.agents ?? [];
  const rows = alerts.data?.alerts ?? [];

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <div className="flex items-start gap-3 rounded-ctl border border-line bg-card-2/40 p-4 text-[13px] text-ink-muted">
        <MonitorCheck className="mt-0.5 h-4 w-4 shrink-0 text-accent" />
        <p>
          Agent-based endpoint detection — <span className="text-ink">lab VMs only</span>. Agents ship normalized OCSF
          telemetry over mutual TLS to a gateway that runs separately from the rest of Argus. Usernames are hashed and
          secrets scrubbed before anything is stored.
        </p>
      </div>

      {error && <div className="rounded-ctl border border-down/30 bg-down/10 px-4 py-2.5 text-[13px] text-down">{error}</div>}

      <Card className="!p-0">
        <div className="p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Endpoints" sub="Agents enrolled with the gateway, their status and last heartbeat." />
        </div>
        {notConfigured ? (
          <Empty>The AED gateway isn't configured in this environment, so there are no endpoints to show.</Empty>
        ) : list.error && !list.data ? (
          <Failed error={list.error} onRetry={list.reload} />
        ) : !list.data ? (
          <Skeleton className="mx-6 mb-6 h-40" />
        ) : !agents.length ? (
          <Empty>No endpoints have enrolled yet.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[720px] text-left text-[13.5px]">
              <thead>
                <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                  <th className="py-3 pl-6 font-medium">Agent</th>
                  <th className="py-3 font-medium">Status</th>
                  <th className="py-3 font-medium">First seen</th>
                  <th className="py-3 font-medium">Last heartbeat</th>
                  <th className="py-3 pr-6 text-right font-medium">{admin ? "Action" : "Version"}</th>
                </tr>
              </thead>
              <tbody>
                {agents.map((a) => (
                  <tr key={a.agent_id} className="border-b border-line/70 odd:bg-zebra">
                    <td className="py-3 pl-6 font-mono">{a.agent_id}</td>
                    <td className="py-3">
                      <StatusPill status={a.status} />
                    </td>
                    <td className="py-3 text-ink-muted" title={dateTime(a.first_seen)}>
                      {ago(a.first_seen)}
                    </td>
                    <td className="py-3 text-ink-muted" title={dateTime(a.last_seen)}>
                      {a.last_seen ? ago(a.last_seen) : "–"}
                    </td>
                    <td className="py-3 pr-6 text-right">
                      {admin ? (
                        <button
                          className="btn-ghost h-8 gap-1.5 !px-2.5 text-down hover:bg-down/10"
                          disabled={!!busy || a.status === "revoked"}
                          onClick={() => revoke(a.agent_id)}
                        >
                          {busy === a.agent_id ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldX className="h-4 w-4" />}
                          {a.status === "revoked" ? "Revoked" : "Revoke"}
                        </button>
                      ) : (
                        <span className="text-ink-muted">{a.version ?? "–"}</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <Card className="!p-0">
        <div className="p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Detections" sub="Alerts raised by the gateway's detection rules on agent telemetry." />
        </div>
        {notConfigured ? (
          <Empty>No gateway configured.</Empty>
        ) : alerts.error && !alerts.data ? (
          <Failed error={alerts.error} onRetry={alerts.reload} />
        ) : !alerts.data ? (
          <Skeleton className="mx-6 mb-6 h-28" />
        ) : !rows.length ? (
          <Empty>No detections. That's the quiet you want.</Empty>
        ) : (
          <ul className="divide-y divide-line/70">
            {rows.map((r, i) => (
              <li key={i} className="flex items-start gap-3 px-6 py-3.5">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-ink">{r.rule}</span>
                    <SevPill sev={r.severity} />
                    <span className="font-mono text-[12.5px] text-ink-muted">{r.agent_id}</span>
                    {r.created_at && <span className="text-[12px] text-ink-faint" title={dateTime(r.created_at)}>{ago(r.created_at)}</span>}
                  </div>
                  <p className="mt-0.5 text-[13px] text-ink-muted">
                    {r.src_ip && <span className="font-mono">{r.src_ip}</span>}
                    {r.count != null && <span> · {r.count} events{r.window_s ? ` in ${r.window_s}s` : ""}</span>}
                    {r.confidence != null && <span> · confidence {Math.round(r.confidence * 100)}%</span>}
                  </p>
                  {r.fp_guidance && <p className="mt-1 text-[12.5px] text-ink-faint">{r.fp_guidance}</p>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
