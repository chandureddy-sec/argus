import { Check, Clock, Copy, Loader2, MonitorCheck, Plus, ShieldAlert, ShieldX, X } from "lucide-react";
import { useEffect, useState } from "react";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Overlay, Segmented } from "../components/ui";
import { post, useApi, type AedAlert, type AedEndpoint, type AedEnrollment, type AedEvent, type Me } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { usePage } from "../lib/page";

/** Onboard an endpoint: pick OS → mint a single-use, 15-min token (shown once)
 * with a copy-able install command and an expiry countdown, then wait for the
 * agent's first heartbeat. The token never persists in the browser. */
function AddEndpoint({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [os, setOs] = useState<"linux" | "windows">("linux");
  const [name, setName] = useState("");
  const [group, setGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string>();
  const [result, setResult] = useState<AedEnrollment>();
  const [copied, setCopied] = useState(false);
  const [left, setLeft] = useState(0);

  useEffect(() => {
    if (!result) return;
    const end = new Date(result.expires_at).getTime();
    const tick = () => setLeft(Math.max(0, Math.round((end - Date.now()) / 1000)));
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [result]);

  const generate = async () => {
    setBusy(true);
    setErr(undefined);
    try {
      setResult(await post<AedEnrollment>("aed/enrollments", { os, name: name || null, group: group || null }));
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const copy = async () => {
    if (!result?.install) return;
    try {
      await navigator.clipboard.writeText(result.install);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard blocked; the command is still selectable */
    }
  };

  const mmss = `${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;

  return (
    <Overlay label="Add endpoint">
      <div className="card w-full max-w-[560px] p-6">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-[16px] font-semibold">Add endpoint</h2>
          <button onClick={onClose} className="rounded-ctl p-1.5 text-ink-muted hover:text-ink" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </div>

        {!result ? (
          <div className="space-y-4">
            <div>
              <span className="label mb-1.5 block">Operating system</span>
              <Segmented value={os} options={["linux", "windows"] as const} onChange={setOs} label="Operating system" />
              {os === "windows" && (
                <p className="mt-2 text-[12.5px] text-warn">The Windows agent isn't built yet — the Linux flow is ready.</p>
              )}
            </div>
            <label className="block">
              <span className="label mb-1.5 block">Name (optional)</span>
              <input value={name} onChange={(e) => setName(e.target.value)} className="ctl w-full" placeholder="lab-vm-1" maxLength={128} />
            </label>
            <label className="block">
              <span className="label mb-1.5 block">Group (optional)</span>
              <input value={group} onChange={(e) => setGroup(e.target.value)} className="ctl w-full" placeholder="lab" maxLength={128} />
            </label>
            {err && <p role="alert" className="rounded-ctl border border-down/30 bg-down/10 px-3 py-2 text-[13px] text-down">{err}</p>}
            <div className="flex justify-end gap-2">
              <button className="btn-ghost" onClick={onClose}>
                Cancel
              </button>
              <button className="btn-primary" onClick={generate} disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Generate token
              </button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <div className="flex items-center justify-between rounded-ctl border border-line bg-card-2/50 px-3 py-2 text-[13px]">
              <span className="flex items-center gap-1.5 text-ink-muted">
                <Clock className="h-4 w-4" /> Single-use token — expires in
              </span>
              <span className={`font-mono tabular-nums ${left < 60 ? "text-down" : "text-ink"}`}>{left > 0 ? mmss : "expired"}</span>
            </div>
            <p className="text-[12.5px] text-ink-faint">Shown once. Run this on the lab VM within the window; the endpoint appears below once it checks in.</p>
            <div>
              <div className="mb-1.5 flex items-center justify-between">
                <span className="label">Install command (Linux)</span>
                <button onClick={copy} className="btn-ghost h-7 gap-1.5 !px-2.5 text-[12.5px]">
                  {copied ? <Check className="h-3.5 w-3.5 text-up" /> : <Copy className="h-3.5 w-3.5" />} {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <pre className="max-h-56 overflow-auto rounded-ctl border border-line bg-card-2/60 p-3 font-mono text-[11.5px] leading-relaxed text-ink">
                {result.install ?? "The gateway isn't serving the agent binary (set AED_AGENT_PATH). Token and CA fingerprint below."}
              </pre>
            </div>
            <div className="grid grid-cols-1 gap-2 text-[12px] text-ink-muted sm:grid-cols-2">
              <div>
                CA fingerprint
                <br />
                <span className="break-all font-mono text-[11px] text-ink-faint">{result.ca_fingerprint}</span>
              </div>
              {result.agent_sha256 && (
                <div>
                  Agent SHA-256
                  <br />
                  <span className="break-all font-mono text-[11px] text-ink-faint">{result.agent_sha256}</span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-2 rounded-ctl border border-line bg-card-2/40 px-3 py-2 text-[13px] text-ink-muted">
              <Loader2 className="h-4 w-4 animate-spin text-accent" /> Waiting for the agent's first heartbeat…
            </div>
            <div className="flex justify-end">
              <button className="btn-primary" onClick={onDone}>
                Done
              </button>
            </div>
          </div>
        )}
      </div>
    </Overlay>
  );
}

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

const CLASS: Record<number, string> = { 3002: "Authentication", 5001: "Device inventory" };

/** One endpoint's detail: its open alerts and a timeline of recent (redacted)
 * events, fetched on open. */
function EndpointDetail({ ep, alerts, onClose }: { ep: AedEndpoint; alerts: AedAlert[]; onClose: () => void }) {
  const evs = useApi<{ events: AedEvent[] }>(`aed/endpoints/${encodeURIComponent(ep.agent_id)}/events`);
  const mine = alerts.filter((a) => a.agent_id === ep.agent_id);
  const rows = evs.data?.events ?? [];
  return (
    <Overlay label={`Endpoint ${ep.agent_id}`}>
      <div className="card flex max-h-[85vh] w-full max-w-[640px] flex-col p-6">
        <div className="mb-4 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <h2 className="font-mono text-[15px] font-semibold">{ep.agent_id}</h2>
            <StatusPill status={ep.status} />
          </div>
          <button onClick={onClose} className="rounded-ctl p-1.5 text-ink-muted hover:text-ink" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </div>

        {mine.length > 0 && (
          <div className="mb-4 space-y-1.5">
            {mine.map((a, i) => (
              <div key={i} className="flex items-start gap-2 rounded-ctl border border-warn/30 bg-warn/10 px-3 py-2 text-[12.5px]">
                <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
                <span>
                  <b className="text-ink">{a.rule}</b>
                  {a.src_ip && (
                    <>
                      {" · "}
                      <span className="font-mono">{a.src_ip}</span>
                    </>
                  )}
                  {a.count != null && <> · {a.count} events</>}
                  {a.fp_guidance && <span className="block text-ink-faint">{a.fp_guidance}</span>}
                </span>
              </div>
            ))}
          </div>
        )}

        <h3 className="label mb-2">Timeline</h3>
        <div className="min-h-0 flex-1 overflow-y-auto">
          {evs.error && !evs.data ? (
            <Failed error={evs.error} onRetry={evs.reload} />
          ) : !evs.data ? (
            <Skeleton className="h-40" />
          ) : !rows.length ? (
            <Empty>No events yet from this endpoint.</Empty>
          ) : (
            <ol className="relative space-y-3 border-l border-line pl-4">
              {rows.map((e, i) => (
                <li key={i} className="relative">
                  <span
                    className={`absolute -left-[21px] top-1 h-2.5 w-2.5 rounded-full ring-2 ring-card ${e.status === "failure" ? "bg-down" : "bg-up"}`}
                  />
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[13px]">
                    <span className="font-medium text-ink">{CLASS[e.class_uid ?? 0] ?? "Event"}</span>
                    {e.status && <span className={e.status === "failure" ? "text-down" : "text-up"}>{e.status}</span>}
                    {e.src_ip && <span className="font-mono text-ink-muted">{e.src_ip}</span>}
                    {e.user && <span className="text-ink-muted">user {e.user}</span>}
                    <span className="ml-auto text-[12px] text-ink-faint" title={e.time ? dateTime(e.time) : undefined}>
                      {e.time ? ago(e.time) : ""}
                    </span>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      </div>
    </Overlay>
  );
}

/** Lab endpoint telemetry served by the AED gateway (admin proxy). Lab VMs only. */
export default function Endpoints({ me }: { me?: Me }) {
  usePage("Response", "Lab endpoints");
  const list = useApi<{ agents: AedEndpoint[] }>("aed/endpoints");
  const alerts = useApi<{ alerts: AedAlert[] }>("aed/alerts");
  const admin = me?.role === "admin";
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [adding, setAdding] = useState(false);
  const [detail, setDetail] = useState<AedEndpoint>();

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
          <CardHead title="Endpoints" sub="Agents enrolled with the gateway, their status and last heartbeat.">
            {admin && !notConfigured && (
              <button className="btn-primary h-8 text-[13px]" onClick={() => setAdding(true)}>
                <Plus className="h-4 w-4" /> Add endpoint
              </button>
            )}
          </CardHead>
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
                    <td className="py-3 pl-6">
                      <button className="font-mono text-accent-soft hover:underline" onClick={() => setDetail(a)}>
                        {a.agent_id}
                      </button>
                    </td>
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

      {adding && (
        <AddEndpoint
          onClose={() => setAdding(false)}
          onDone={() => {
            setAdding(false);
            list.reload();
          }}
        />
      )}
      {detail && <EndpointDetail ep={detail} alerts={rows} onClose={() => setDetail(undefined)} />}
    </div>
  );
}
