import { Activity, ChevronDown, ChevronRight, Copy, Loader2, Pencil, Plus, Send, Trash2, Upload, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Overlay } from "../components/ui";
import { send, useV1, type Me } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { usePage } from "../lib/page";

interface FieldSpec {
  name: string;
  label: string;
  required: boolean;
  kind: "text" | "url" | "int" | "bool" | "list" | "password";
  hint: string;
  default: unknown;
}

interface KindSpec {
  kind: string;
  title: string;
  role: "indicators" | "alerts" | "both";
  docs: string;
  config: FieldSpec[];
  secret: FieldSpec[];
}

interface Integration {
  id: number;
  name: string;
  kind: string;
  kindTitle: string;
  role: KindSpec["role"];
  enabled: boolean;
  config: Record<string, unknown>;
  hasSecret: boolean;
  allowInternal: boolean;
  minScore: number;
  maxTlp: string;
  types: string[];
  intervalMinutes: number;
  lastRunAt: string | null;
  lastStatus: string | null;
  lastError: string | null;
  cursor: string | null;
}

interface Run {
  id: number;
  trigger: string;
  startedAt: string;
  status: string;
  sent: number;
  heldBack: number;
  error: string | null;
  detail: Record<string, unknown>;
}

interface Sharing {
  preview: { qualifying: number; tlp: number; licence_or_type: number; shareable: number };
  taxii: { discovery: string; apiRoot: string; collections: { id: string; title: string; description: string; maxTlp: string; minScore: number; url: string }[] };
  exports: { format: string; media: string; types: string[] }[];
  exportPath: string;
}

const TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"];
const TYPES: [string, string][] = [["ipv4-addr", "IPv4"], ["ipv6-addr", "IPv6"], ["ipv4-net", "IPv4 ranges"], ["domain-name", "Domains"], ["url", "URLs"], ["file-sha256", "SHA-256"], ["file-md5", "MD5"], ["email-addr", "Email"]];
const STATUS_TONE: Record<string, string> = { success: "text-up", partial: "text-warn", failed: "text-down", running: "text-info-soft", skipped: "text-ink-muted" };

function CopyLine({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <span className="flex min-w-0 items-center gap-2">
      <code className="min-w-0 flex-1 truncate rounded bg-card-2 px-2 py-1 text-[12px]">{value}</code>
      <button
        type="button"
        className="btn-ghost h-7 w-7 !px-0"
        aria-label="Copy"
        onClick={() => {
          void navigator.clipboard?.writeText(value).then(() => {
            setDone(true);
            setTimeout(() => setDone(false), 1200);
          });
        }}
      >
        {done ? "✓" : <Copy className="h-3.5 w-3.5" />}
      </button>
    </span>
  );
}

function SharingCard() {
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [score, setScore] = useState(60);
  const { data, error, reload } = useV1<Sharing>("sharing", { max_tlp: tlp, min_score: score });
  return (
    <Card>
      <CardHead title="What we share, and where" sub="Every outbound path applies the same rules: TLP:RED never leaves, nothing above the destination's marking, nothing from a source whose licence forbids redistribution" />
      {error && !data ? (
        <Failed error={error} onRetry={reload} />
      ) : !data ? (
        <Skeleton className="h-40" />
      ) : (
        <div className="grid gap-6 xl:grid-cols-3">
          <section>
            <p className="label mb-2">Preview</p>
            <div className="flex flex-wrap items-center gap-2 text-[13px]">
              <select className="ctl h-8 text-[13px]" value={tlp} onChange={(e) => setTlp(e.target.value)} aria-label="Most restricted marking">
                {TLPS.map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
              <label className="flex items-center gap-1.5">
                score ≥ <input type="number" min={0} max={100} value={score} onChange={(e) => setScore(Number(e.target.value))} className="ctl h-8 w-20 text-[13px]" />
              </label>
            </div>
            <dl className="mt-3 grid grid-cols-2 gap-2 text-[13px]">
              <dt className="text-ink-muted">Qualifying indicators</dt>
              <dd className="text-right tabular-nums">{data.preview.qualifying.toLocaleString()}</dd>
              <dt className="text-ink-muted">Shareable</dt>
              <dd className="text-right font-semibold tabular-nums text-up">{data.preview.shareable.toLocaleString()}</dd>
              <dt className="text-ink-muted">Kept: marking too strict</dt>
              <dd className="text-right tabular-nums">{data.preview.tlp.toLocaleString()}</dd>
              <dt className="text-ink-muted">Kept: licence or type</dt>
              <dd className="text-right tabular-nums">{data.preview.licence_or_type.toLocaleString()}</dd>
            </dl>
          </section>
          <section>
            <p className="label mb-2">TAXII 2.1 (read-only)</p>
            <p className="mb-2 text-[12.5px] text-ink-muted">Any TAXII client, MISP or another Argus can pull these with an API key (HTTP Basic: the key is the password). Readers see collections up to their TLP clearance.</p>
            <CopyLine value={data.taxii.discovery} />
            <ul className="mt-3 space-y-2">
              {data.taxii.collections.map((c) => (
                <li key={c.id} className="text-[12.5px]">
                  <p className="font-medium">{c.title}</p>
                  <CopyLine value={c.url} />
                </li>
              ))}
            </ul>
          </section>
          <section>
            <p className="label mb-2">Exports (feed token)</p>
            <p className="mb-2 text-[12.5px] text-ink-muted">
              Point a firewall EDL, Wazuh or a script at <code className="text-[12px]">{data.exportPath}</code>. Create the token under Settings → Feed export.
            </p>
            <div className="flex flex-wrap gap-1.5">
              {data.exports.map((e) => (
                <span key={e.format} className="rounded bg-chip px-2 py-0.5 font-mono text-[12px] text-chip-ink ring-1 ring-line" title={e.media}>
                  {e.format}
                </span>
              ))}
            </div>
          </section>
        </div>
      )}
    </Card>
  );
}

type FormState = {
  id?: number;
  name: string;
  kind: string;
  enabled: boolean;
  config: Record<string, string | boolean>;
  secret: Record<string, string>;
  allow_internal: boolean;
  min_score: number;
  max_tlp: string;
  types: string[];
  interval_minutes: number;
};

function IntegrationForm({ kinds, initial, onClose, onSaved }: { kinds: KindSpec[]; initial?: Integration; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<FormState>(() =>
    initial
      ? {
          id: initial.id, name: initial.name, kind: initial.kind, enabled: initial.enabled,
          config: Object.fromEntries(Object.entries(initial.config).map(([k, v]) => [k, typeof v === "boolean" ? v : Array.isArray(v) ? v.join(", ") : String(v ?? "")])),
          secret: {}, allow_internal: initial.allowInternal, min_score: initial.minScore, max_tlp: initial.maxTlp,
          types: initial.types, interval_minutes: initial.intervalMinutes,
        }
      : { name: "", kind: kinds[0]?.kind ?? "splunk_hec", enabled: true, config: {}, secret: {}, allow_internal: false, min_score: 60, max_tlp: "TLP:GREEN", types: [], interval_minutes: 60 },
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const spec = kinds.find((k) => k.kind === f.kind);
  const sendsIndicators = spec?.role !== "alerts";

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const body = { ...f, secret: Object.fromEntries(Object.entries(f.secret).filter(([, v]) => v.trim())) };
      delete (body as { id?: number }).id;
      if (f.id) await send("PUT", `/api/v1/integrations/${f.id}`, body);
      else await send("POST", "/api/v1/integrations", body);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const field = (fs: FieldSpec, secret: boolean) => {
    const val = secret ? f.secret[fs.name] ?? "" : f.config[fs.name] ?? (fs.default as string | boolean | undefined) ?? "";
    const put = (v: string | boolean) => setF((x) => (secret ? { ...x, secret: { ...x.secret, [fs.name]: String(v) } } : { ...x, config: { ...x.config, [fs.name]: v } }));
    if (fs.kind === "bool") {
      return (
        <label key={fs.name} className="flex items-center gap-2 text-[13px]">
          <input type="checkbox" className="h-4 w-4 accent-accent" checked={val === true || val === "true"} onChange={(e) => put(e.target.checked)} /> {fs.label}
        </label>
      );
    }
    return (
      <label key={fs.name} className="block text-[13px]">
        <span className="mb-1 block text-ink-muted">
          {fs.label}
          {!fs.required && <span className="text-ink-faint"> (optional)</span>}
        </span>
        <input
          className="ctl w-full"
          type={fs.kind === "password" ? "password" : fs.kind === "int" ? "number" : "text"}
          autoComplete={fs.kind === "password" ? "new-password" : "off"}
          value={String(val)}
          placeholder={secret && initial?.hasSecret ? "Leave empty to keep the stored value" : fs.hint}
          onChange={(e) => put(e.target.value)}
          spellCheck={false}
        />
      </label>
    );
  };

  return (
    <Overlay label={initial ? `Edit ${initial.name}` : "Add an integration"}>
      <form onSubmit={save} className="w-full max-w-[640px] space-y-5 rounded-card border border-line bg-card p-6 shadow-2xl" autoComplete="off">
        <header className="flex items-center justify-between">
          <h2 className="text-[17px] font-semibold">{initial ? `Edit ${initial.name}` : "Add an integration"}</h2>
          <button type="button" className="btn-ghost h-8 w-8 !px-0" onClick={onClose} aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </header>
        <div className="grid gap-4 sm:grid-cols-2">
          <label className="block text-[13px]">
            <span className="mb-1 block text-ink-muted">Kind</span>
            <select className="ctl w-full" value={f.kind} disabled={!!initial} onChange={(e) => setF({ ...f, kind: e.target.value, config: {}, secret: {} })}>
              {kinds.map((k) => (
                <option key={k.kind} value={k.kind}>
                  {k.title} · {k.role === "alerts" ? "alerts" : k.role === "both" ? "indicators or alerts" : "indicators"}
                </option>
              ))}
            </select>
          </label>
          <label className="block text-[13px]">
            <span className="mb-1 block text-ink-muted">Name</span>
            <input className="ctl w-full font-mono" value={f.name} disabled={!!initial} onChange={(e) => setF({ ...f, name: e.target.value.toLowerCase() })} placeholder="e.g. soc-splunk" pattern="[a-z0-9][a-z0-9_-]{1,62}" required />
          </label>
          {spec?.config.map((x) => field(x, false))}
          {spec?.secret.map((x) => field(x, true))}
        </div>
        <fieldset className="grid gap-4 border-t border-line pt-4 sm:grid-cols-2">
          <legend className="mb-2 text-[13.5px] font-semibold">What it may receive</legend>
          <label className="block text-[13px]">
            <span className="mb-1 block text-ink-muted">Most restricted marking</span>
            <select className="ctl w-full" value={f.max_tlp} onChange={(e) => setF({ ...f, max_tlp: e.target.value })}>
              {TLPS.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          {sendsIndicators && (
            <>
              <label className="block text-[13px]">
                <span className="mb-1 block text-ink-muted">Minimum score</span>
                <input type="number" min={0} max={100} className="ctl w-full" value={f.min_score} onChange={(e) => setF({ ...f, min_score: Number(e.target.value) })} />
              </label>
              <label className="block text-[13px]">
                <span className="mb-1 block text-ink-muted">Push every (minutes)</span>
                <input type="number" min={5} max={10080} className="ctl w-full" value={f.interval_minutes} onChange={(e) => setF({ ...f, interval_minutes: Number(e.target.value) })} />
              </label>
              <div className="text-[13px] sm:col-span-2">
                <span className="mb-1 block text-ink-muted">Types (none ticked: all)</span>
                <div className="flex flex-wrap gap-3">
                  {TYPES.map(([v, l]) => (
                    <label key={v} className="flex items-center gap-1.5">
                      <input type="checkbox" className="h-4 w-4 accent-accent" checked={f.types.includes(v)} onChange={(e) => setF({ ...f, types: e.target.checked ? [...f.types, v] : f.types.filter((t) => t !== v) })} />
                      {l}
                    </label>
                  ))}
                </div>
              </div>
            </>
          )}
          <label className="flex items-start gap-2 text-[13px] text-ink-muted sm:col-span-2">
            <input type="checkbox" className="mt-0.5 h-4 w-4 accent-accent" checked={f.allow_internal} onChange={(e) => setF({ ...f, allow_internal: e.target.checked })} />
            <span>In our internal network (a SIEM or MISP in the LAN): private addresses and plain http allowed for this integration only. Cloud-metadata addresses stay blocked.</span>
          </label>
          <label className="flex items-center gap-2 text-[13px] sm:col-span-2">
            <input type="checkbox" className="h-4 w-4 accent-accent" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} /> Enabled
          </label>
        </fieldset>
        {spec?.docs && (
          <p className="text-[12px] text-ink-faint">
            Vendor docs: <a className="underline" href={spec.docs} target="_blank" rel="noreferrer noopener">{spec.docs}</a>
          </p>
        )}
        {error && <p role="alert" className="rounded-ctl border border-down/30 bg-down/[0.07] px-3 py-2 text-[13px] text-down">{error}</p>}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost h-9" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary h-9" disabled={busy}>
            {busy && <Loader2 className="h-4 w-4 animate-spin" />} {initial ? "Save" : "Add"}
          </button>
        </div>
      </form>
    </Overlay>
  );
}

function Runs({ id }: { id: number }) {
  const { data, error, reload } = useV1<Run[]>(`integrations/${id}/runs`);
  if (error && !data) return <Failed error={error} onRetry={reload} />;
  if (!data) return <Skeleton className="h-16" />;
  if (!data.length) return <p className="text-[12.5px] text-ink-faint">No runs yet.</p>;
  return (
    <table className="w-full text-[12.5px]">
      <tbody>
        {data.map((r) => (
          <tr key={r.id} className="border-t border-line/60">
            <td className="py-1.5 pr-3 text-ink-muted">{dateTime(r.startedAt)}</td>
            <td className="py-1.5 pr-3">{r.trigger}</td>
            <td className={`py-1.5 pr-3 font-medium ${STATUS_TONE[r.status] ?? ""}`}>{r.status}</td>
            <td className="py-1.5 pr-3 tabular-nums">{r.sent.toLocaleString()} sent{r.heldBack ? ` · ${r.heldBack} kept` : ""}</td>
            <td className="py-1.5 text-ink-muted">{r.error ?? (typeof r.detail?.result === "string" ? r.detail.result : "")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function Integrations({ me }: { me?: Me }) {
  usePage("Platform", "Integrations");
  const admin = me?.role === "admin";
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <SharingCard />
      {admin ? (
        <AdminIntegrations />
      ) : (
        <Card>
          <p className="flex items-center gap-2 text-[13px] text-ink-muted">
            <Send className="h-4 w-4" /> Integrations are managed by admins.
          </p>
        </Card>
      )}
    </div>
  );
}

function AdminIntegrations() {
  const { data, error, reload } = useV1<{ items: Integration[]; kinds: KindSpec[] }>("integrations");
  const [editing, setEditing] = useState<Integration | "new">();
  const [open, setOpen] = useState<number>();
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>();

  const act = async (key: string, fn: () => Promise<{ result?: string; sent?: number; status?: string; error?: string | null } | unknown>) => {
    setBusy(key);
    setMsg(undefined);
    try {
      const r = (await fn()) as { result?: string; sent?: number; status?: string; error?: string | null } | undefined;
      const text = r?.result ?? (r?.status ? `Push ${r.status}: ${r.sent ?? 0} sent${r.error ? ` (${r.error})` : ""}` : "Done");
      setMsg({ ok: r?.status !== "failed", text });
      reload();
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <>
      {(
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Integrations" sub="SIEMs and TIPs that receive indicators, and channels that receive alerts. Secrets are stored encrypted and never shown again.">
              <button className="btn-primary h-9" onClick={() => setEditing("new")} disabled={!data}>
                <Plus className="h-4 w-4" /> Add
              </button>
            </CardHead>
            {msg && <p className={`text-[13px] ${msg.ok ? "text-up" : "text-down"}`}>{msg.text}</p>}
          </div>
          {error && !data ? (
            <Failed error={error} onRetry={reload} />
          ) : !data ? (
            <Skeleton className="mx-6 mb-6 h-32" />
          ) : !data.items.length ? (
            <Empty>No integrations yet. Add Splunk, Elastic, Sentinel, MISP or a webhook to push indicators, or Slack, Teams, Telegram or email for alerts.</Empty>
          ) : (
            <ul className="divide-y divide-line border-t border-line">
              {data.items.map((i) => (
                <li key={i.id} className="px-5 py-3 sm:px-6">
                  <div className="flex flex-wrap items-center gap-3">
                    <button className="btn-ghost h-7 w-7 !px-0" onClick={() => setOpen(open === i.id ? undefined : i.id)} aria-label="Show runs">
                      {open === i.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    </button>
                    <div className="min-w-0 flex-1">
                      <p className="font-medium">
                        <span className="font-mono">{i.name}</span> <span className="text-[12.5px] font-normal text-ink-muted">· {i.kindTitle}</span>
                        {!i.enabled && <span className="ml-2 rounded bg-chip px-1.5 text-[11.5px] text-chip-ink">off</span>}
                      </p>
                      <p className="text-[12px] text-ink-faint">
                        {i.role === "alerts" ? "alerts" : `indicators ≥ ${i.minScore}${i.types.length ? ` (${i.types.join(", ")})` : ""}, every ${i.intervalMinutes} min`} · up to {i.maxTlp}
                        {i.allowInternal && " · internal network"}
                        {i.lastRunAt && (
                          <>
                            {" "}· last <span className={STATUS_TONE[i.lastStatus ?? ""] ?? ""}>{i.lastStatus}</span> {ago(i.lastRunAt)}
                          </>
                        )}
                      </p>
                      {i.lastError && <p className="text-[12px] text-down">{i.lastError}</p>}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      <button className="btn-ghost h-8 text-[13px]" disabled={!!busy} onClick={() => act(`t${i.id}`, () => send("POST", `/api/v1/integrations/${i.id}/test`))}>
                        {busy === `t${i.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Activity className="h-4 w-4" />} Test
                      </button>
                      {i.role !== "alerts" && (
                        <button className="btn-ghost h-8 text-[13px]" disabled={!!busy} onClick={() => act(`p${i.id}`, () => send("POST", `/api/v1/integrations/${i.id}/push`))}>
                          {busy === `p${i.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />} Push now
                        </button>
                      )}
                      <button className="btn-ghost h-8 w-8 !px-0" onClick={() => setEditing(i)} aria-label={`Edit ${i.name}`}>
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button className="btn-ghost h-8 w-8 !px-0 hover:!text-down" disabled={!!busy} onClick={() => act(`d${i.id}`, () => send("DELETE", `/api/v1/integrations/${i.id}`))} aria-label={`Delete ${i.name}`}>
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </div>
                  {open === i.id && (
                    <div className="mt-3 pl-10">
                      <Runs id={i.id} />
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </Card>
      )}
      {editing && data && (
        <IntegrationForm
          kinds={data.kinds}
          initial={editing === "new" ? undefined : editing}
          onClose={() => setEditing(undefined)}
          onSaved={() => {
            setEditing(undefined);
            reload();
          }}
        />
      )}
    </>
  );
}
