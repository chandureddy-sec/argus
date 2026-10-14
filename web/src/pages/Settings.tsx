import { KeyRound, Loader2, Plus, Save, ShieldCheck, Trash2 } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { CopyButton, Ioc } from "../components/intel";
import { Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { post, send, useApi } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

interface Policy {
  known_bad_days: number;
  suspect_days: number;
  manual_days: number;
  known_bad_score: number;
  export_max_tlp: string;
  require_second_approver: boolean;
}

interface SettingsData {
  policy: Policy;
  exportTlps: string[];
  formats: string[];
  exported: Record<string, number>;
  base: string;
  canEdit: boolean;
  tokens: { id: number; name: string; prefix: string; createdBy: string; createdAt: string; lastUsedAt: string | null; revokedAt: string | null }[];
}

interface Never {
  manual: { id: number; kind: string; value: string; reason: string; createdBy: string | null }[];
  own: { id: number; kind: string; value: string; reason: string }[];
  assets: Record<string, number>;
  resolvers: string[];
  canEdit: boolean;
}

const FORMAT_HINT: Record<string, string> = {
  "ip.txt": "IPs and CIDR ranges, one per line (firewall IP list)",
  "domain.txt": "domains (firewall domain list)",
  "url.txt": "URLs without scheme (firewall URL list)",
  "blocks.csv": "every field, for spreadsheets and SIEM lookups",
  "blocks.json": "every field, for scripts",
  "stix.json": "STIX 2.1 bundle, TLP-marked",
};

function PolicyCard({ s, reload }: { s: SettingsData; reload: () => void }) {
  const [p, setP] = useState<Policy>(s.policy);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>();
  useEffect(() => setP(s.policy), [s.policy]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(undefined);
    try {
      await send("PUT", "/app/api/settings/policy", { ...p, known_bad_days: Number(p.known_bad_days), suspect_days: Number(p.suspect_days), manual_days: Number(p.manual_days), known_bad_score: Number(p.known_bad_score) });
      setMsg({ ok: true, text: "Saved" });
      reload();
    } catch (err) {
      setMsg({ ok: false, text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const num = (k: keyof Policy, label: string, min: number, max: number) => (
    <label className="block">
      <span className="label mb-1.5 block">{label}</span>
      <input type="number" min={min} max={max} value={p[k] as number} onChange={(e) => setP({ ...p, [k]: e.target.value })} className="ctl w-full" required />
    </label>
  );
  return (
    <Card>
      <CardHead title="Blocking policy" sub={s.canEdit ? "How long blocks last and who may enforce them" : "Read only: changes need the admin role"} />
      <form onSubmit={save} className="space-y-4">
        <fieldset disabled={!s.canEdit || busy} className="grid gap-4 sm:grid-cols-2">
          {num("known_bad_days", "Known-bad block (days)", 1, 365)}
          {num("suspect_days", "Suspect block (days)", 1, 365)}
          {num("manual_days", "Manual block (days)", 1, 365)}
          {num("known_bad_score", "Known-bad from score", 0, 100)}
          <label className="block">
            <span className="label mb-1.5 block">Export up to</span>
            <select value={p.export_max_tlp} onChange={(e) => setP({ ...p, export_max_tlp: e.target.value })} className="ctl w-full">
              {s.exportTlps.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 self-end pb-2 text-[13.5px]">
            <input type="checkbox" className="h-4 w-4 accent-[#1F6BFF]" checked={p.require_second_approver} onChange={(e) => setP({ ...p, require_second_approver: e.target.checked })} /> Enforcing needs a second admin
          </label>
        </fieldset>
        <ul className="space-y-1 text-[12.5px] text-ink-muted">
          <li><b className="text-ink">Known bad</b>: an active indicator at or above the score. <b className="text-ink">Manual</b>: typed into the blocklist. <b className="text-ink">Suspect</b>: everything else.</li>
          <li><b className="text-ink">Second admin</b>: whoever asks for enforce can't approve it. Turn off only if you are the sole admin.</li>
          <li><b className="text-ink">Export up to</b>: blocks marked above this never reach a device. TLP:RED is never exported.</li>
        </ul>
        {s.canEdit && (
          <div className="flex items-center gap-3">
            <button className="btn-primary" disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save policy
            </button>
            {msg && <span className={`text-[13px] ${msg.ok ? "text-up" : "text-down"}`}>{msg.text}</span>}
          </div>
        )}
      </form>
    </Card>
  );
}

function ExportCard({ s, reload }: { s: SettingsData; reload: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<string>();
  const [made, setMade] = useState<{ name: string; token: string; urls: string[] }>();
  const [error, setError] = useState<string>();
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("new");
    setError(undefined);
    try {
      setMade(await post("settings/tokens", { name }));
      setName("");
      reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const revoke = async (id: number) => {
    if (!window.confirm("Revoke this token? Devices using it stop getting updates at once.")) return;
    setBusy(String(id));
    try {
      await post(`settings/tokens/${id}/revoke`);
      reload();
    } finally {
      setBusy(undefined);
    }
  };
  const ips = (s.exported.ip ?? 0) + (s.exported.cidr ?? 0);
  return (
    <Card>
      <CardHead title="Feed export" sub={`${ips} IPs and ranges · ${s.exported.domain ?? 0} domains · ${s.exported.url ?? 0} URLs published now. Only enforced, unexpired blocks are published, after a second never-block check.`} />
      {made && (
        <div className="mb-5 rounded-card border border-warn/40 bg-warn/[0.06] p-4" aria-live="polite">
          <p className="mb-2 flex items-center gap-2 text-[13.5px] font-semibold text-warn">
            <KeyRound className="h-4 w-4" /> Token for {made.name}: copy it now, it is shown once
          </p>
          <p className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
            <span className="select-all break-all">{made.token}</span> <CopyButton value={made.token} />
          </p>
          <ul className="mt-3 space-y-1 font-mono text-[12px] text-ink-muted">
            {made.urls.map((u) => (
              <li key={u} className="select-all break-all">{u}</li>
            ))}
          </ul>
        </div>
      )}
      <ul className="mb-5 space-y-1.5">
        {s.formats.map((f) => (
          <li key={f} className="text-[12.5px]">
            <span className="font-mono text-ink-muted">{s.base}/feeds/&lt;token&gt;/{f}</span>
            <span className="block text-ink-faint">{FORMAT_HINT[f] ?? ""}</span>
          </li>
        ))}
      </ul>
      <h3 className="mb-2 text-[13.5px] font-semibold">Tokens</h3>
      {s.tokens.length ? (
        <ul className="mb-4 divide-y divide-line/70 rounded-ctl border border-line">
          {s.tokens.map((t) => (
            <li key={t.id} className={`flex items-center gap-3 px-3 py-2.5 text-[13px] ${t.revokedAt ? "opacity-50" : ""}`}>
              <span className="min-w-0 flex-1">
                <b>{t.name}</b> <span className="font-mono text-ink-faint">{t.prefix}…</span>
                <span className="block text-[12px] text-ink-faint">
                  made by {t.createdBy} {ago(t.createdAt)} · last pull {ago(t.lastUsedAt)}
                  {t.revokedAt && ` · revoked ${ago(t.revokedAt)}`}
                </span>
              </span>
              {!t.revokedAt && s.canEdit && (
                <button className="btn-ghost h-8 text-[12.5px] hover:!text-down" onClick={() => revoke(t.id)} disabled={!!busy}>
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mb-4 text-[13px] text-ink-muted">No tokens yet: nothing can pull the feed.</p>
      )}
      {s.canEdit && (
        <form onSubmit={create} className="flex gap-2">
          <input value={name} onChange={(e) => setName(e.target.value)} className="ctl flex-1" placeholder="New token for, e.g. hq-palo-alto" maxLength={64} required />
          <button className="btn-primary" disabled={busy === "new"}>
            {busy === "new" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Create token
          </button>
        </form>
      )}
      {error && <p className="mt-2 text-[13px] text-down">{error}</p>}
    </Card>
  );
}

function NeverBlockCard() {
  const { data, error, reload } = useApi<Never>("neverblock");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>();
  if (error && !data) return <Card><Failed error={error} onRetry={reload} /></Card>;
  if (!data) return <Card><Skeleton className="h-40" /></Card>;
  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(undefined);
    try {
      await post("neverblock", { value, reason });
      setValue("");
      setReason("");
      reload();
    } catch (err) {
      setMsg((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHead title="Never block" sub="Checked on every block and every export. Indicators on these stay visible and labelled, so a compromise of your own host is still noticed." />
      <div className="mb-4 grid gap-3 text-[12.5px] sm:grid-cols-3">
        <div className="rounded-ctl border border-line bg-card-2/40 p-3"><p className="text-ink-faint">Your assets</p><p className="text-[18px] font-bold">{Object.values(data.assets).reduce((a, b) => a + b, 0)}</p></div>
        <div className="rounded-ctl border border-line bg-card-2/40 p-3"><p className="text-ink-faint">From your org profile</p><p className="text-[18px] font-bold">{data.own.length}</p></div>
        <div className="rounded-ctl border border-line bg-card-2/40 p-3"><p className="text-ink-faint">Public DNS resolvers</p><p className="text-[18px] font-bold">{data.resolvers.length}</p></div>
      </div>
      <p className="mb-3 flex items-center gap-2 text-[12.5px] text-ink-muted"><ShieldCheck className="h-4 w-4 text-up" /> Private, loopback, link-local and documentation ranges are always protected.</p>
      {data.manual.length > 0 && (
        <ul className="mb-4 divide-y divide-line/70 rounded-ctl border border-line">
          {data.manual.map((m) => (
            <li key={m.id} className="flex items-center gap-3 px-3 py-2.5 text-[13px]">
              <Ioc value={m.value} className="text-[13px]" />
              <span className="min-w-0 flex-1 truncate text-ink-muted">{m.reason}</span>
              {data.canEdit && (
                <button className="btn-ghost h-8 w-8 !px-0 hover:!text-down" aria-label={`Remove ${m.value}`} onClick={async () => { await send("DELETE", `/app/api/neverblock/${m.id}`); reload(); }}>
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {data.canEdit && (
        <form onSubmit={add} className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
          <input value={value} onChange={(e) => setValue(e.target.value)} className="ctl font-mono" placeholder="IP, CIDR range or domain" required />
          <input value={reason} onChange={(e) => setReason(e.target.value)} className="ctl" placeholder="Why it is ours" minLength={3} required />
          <button className="btn-primary" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add
          </button>
        </form>
      )}
      {msg && <p className="mt-2 text-[13px] text-down">{msg}</p>}
    </Card>
  );
}

export default function Settings() {
  usePage("Platform", "Settings");
  const { data, error, reload } = useApi<SettingsData>("settings");
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      {error && !data ? (
        <Card><Failed error={error} onRetry={reload} /></Card>
      ) : !data ? (
        <Skeleton className="h-80" />
      ) : (
        <>
          <div className="grid gap-6 xl:grid-cols-2">
            <PolicyCard s={data} reload={reload} />
            <ExportCard s={data} reload={reload} />
          </div>
          <NeverBlockCard />
        </>
      )}
    </div>
  );
}
