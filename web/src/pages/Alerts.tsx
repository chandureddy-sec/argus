import { BellRing, Loader2, Play, Plus, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { TlpTag } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { send, useV1, type Me } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

interface Rule {
  id: number;
  name: string;
  kind: "score" | "pir" | "kev_asset" | "environment";
  enabled: boolean;
  params: { min_score?: number };
  channels: number[];
  maxTlp: string;
  since: string | null;
}

interface AlertRow {
  id: number;
  rule: string;
  title: string;
  lines: string[];
  link: string | null;
  tlp: string;
  createdAt: string;
  delivered: Record<string, string>;
}

interface Channel {
  id: number;
  name: string;
  kindTitle: string;
  role: string;
  maxTlp: string;
}

const KINDS: [Rule["kind"], string, string][] = [
  ["score", "High-priority indicator", "An indicator reaches the minimum score"],
  ["pir", "Matches our priorities", "An indicator matches a PIR, our sector, stack or assets"],
  ["kev_asset", "Exploited CVE in our stack", "CISA adds a CVE affecting software we run"],
  ["environment", "Seen in our environment", "Our SIEM saw a value we hold at the minimum score"],
];
const DEFAULT_MIN: Record<string, number> = { score: 80, pir: 30, environment: 60 };
const TLPS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"];

function RuleForm({ channels, onSaved }: { channels: Channel[]; onSaved: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<Rule["kind"]>("score");
  const [min, setMin] = useState(80);
  const [chosen, setChosen] = useState<number[]>([]);
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await send("POST", "/api/v1/alerts/rules", { name, kind, params: kind in DEFAULT_MIN ? { min_score: min } : {}, channels: chosen, max_tlp: tlp });
      setName("");
      setChosen([]);
      onSaved();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (!channels.length) {
    return (
      <Empty>
        Add a Slack, Teams, Telegram, email or webhook channel under <Link className="underline" to="/integrations">Integrations</Link> first.
      </Empty>
    );
  }
  return (
    <form onSubmit={submit} className="grid gap-3 rounded-ctl border border-line bg-card-2/30 p-4 sm:grid-cols-2 xl:grid-cols-4">
      <label className="block text-[13px]">
        <span className="mb-1 block text-ink-muted">Name</span>
        <input className="ctl w-full" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Block-worthy C2" required minLength={2} maxLength={100} />
      </label>
      <label className="block text-[13px]">
        <span className="mb-1 block text-ink-muted">When</span>
        <select className="ctl w-full" value={kind} onChange={(e) => { const k = e.target.value as Rule["kind"]; setKind(k); setMin(DEFAULT_MIN[k] ?? 0); }}>
          {KINDS.map(([k, l]) => (
            <option key={k} value={k}>{l}</option>
          ))}
        </select>
      </label>
      {kind in DEFAULT_MIN ? (
        <label className="block text-[13px]">
          <span className="mb-1 block text-ink-muted">Minimum score</span>
          <input type="number" min={0} max={100} className="ctl w-full" value={min} onChange={(e) => setMin(Number(e.target.value))} />
        </label>
      ) : (
        <span />
      )}
      <label className="block text-[13px]">
        <span className="mb-1 block text-ink-muted">Most restricted marking in a message</span>
        <select className="ctl w-full" value={tlp} onChange={(e) => setTlp(e.target.value)}>
          {TLPS.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
      </label>
      <div className="text-[13px] sm:col-span-2 xl:col-span-3">
        <span className="mb-1 block text-ink-muted">Send to</span>
        <div className="flex flex-wrap gap-3">
          {channels.map((c) => (
            <label key={c.id} className="flex items-center gap-1.5">
              <input type="checkbox" className="h-4 w-4 accent-accent" checked={chosen.includes(c.id)} onChange={(e) => setChosen(e.target.checked ? [...chosen, c.id] : chosen.filter((x) => x !== c.id))} />
              <span className="font-mono">{c.name}</span> <span className="text-ink-faint">({c.kindTitle}, up to {c.maxTlp})</span>
            </label>
          ))}
        </div>
      </div>
      <div className="flex items-end justify-end">
        <button className="btn-primary h-9" disabled={busy || !chosen.length || !name.trim()}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add rule
        </button>
      </div>
      {error && <p role="alert" className="text-[13px] text-down sm:col-span-2 xl:col-span-4">{error}</p>}
    </form>
  );
}

function AdminRules() {
  const rules = useV1<Rule[]>("alerts/rules");
  const ints = useV1<{ items: Channel[] }>("integrations");
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const channels = (ints.data?.items ?? []).filter((c) => c.role !== "indicators");
  const name = (id: number) => channels.find((c) => c.id === id)?.name ?? `#${id} (removed)`;
  const act = async (key: string, fn: () => Promise<unknown>, done?: (r: unknown) => string) => {
    setBusy(key);
    setMsg(undefined);
    try {
      const r = await fn();
      if (done) setMsg(done(r));
      rules.reload();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  return (
    <Card>
      <CardHead title="Alert rules" sub="Each alert is sent once, only to channels allowed its marking, at most 20 per channel per hour (the rest arrive as one summary). A new rule starts from now.">
        <button
          className="btn-ghost h-8 text-[13px]"
          disabled={!!busy}
          onClick={() => act("eval", () => send("POST", "/api/v1/alerts/evaluate"), (r) => {
            const x = r as { raised: number; delivered: number; held: number };
            return `${x.raised} raised · ${x.delivered} sent · ${x.held} held`;
          })}
        >
          {busy === "eval" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Check now
        </button>
      </CardHead>
      {msg && <p className="mb-3 text-[13px] text-ink-muted">{msg}</p>}
      {rules.error && !rules.data ? (
        <Failed error={rules.error} onRetry={rules.reload} />
      ) : !rules.data ? (
        <Skeleton className="h-20" />
      ) : (
        <div className="space-y-4">
          {rules.data.length > 0 && (
            <ul className="divide-y divide-line rounded-ctl border border-line">
              {rules.data.map((r) => (
                <li key={r.id} className="flex flex-wrap items-center gap-3 px-4 py-2.5 text-[13px]">
                  <span className="min-w-0 flex-1">
                    <b>{r.name}</b> <span className="text-ink-muted">· {KINDS.find(([k]) => k === r.kind)?.[1]}{r.params.min_score != null ? ` ≥ ${r.params.min_score}` : ""} · up to {r.maxTlp}</span>
                    <span className="block text-[12px] text-ink-faint">to {r.channels.map(name).join(", ")} · checking since {ago(r.since)}</span>
                  </span>
                  <label className="flex items-center gap-1.5 text-[12.5px]">
                    <input type="checkbox" className="h-4 w-4 accent-accent" checked={r.enabled} disabled={!!busy}
                      onChange={(e) => act(`e${r.id}`, () => send("PUT", `/api/v1/alerts/rules/${r.id}`, { name: r.name, kind: r.kind, params: r.params, channels: r.channels, max_tlp: r.maxTlp, enabled: e.target.checked }))} />
                    on
                  </label>
                  <button className="btn-ghost h-8 w-8 !px-0 hover:!text-down" disabled={!!busy} onClick={() => act(`d${r.id}`, () => send("DELETE", `/api/v1/alerts/rules/${r.id}`))} aria-label={`Delete ${r.name}`}>
                    <Trash2 className="h-4 w-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
          {ints.data && <RuleForm channels={channels} onSaved={rules.reload} />}
        </div>
      )}
    </Card>
  );
}

export default function Alerts({ me }: { me?: Me }) {
  usePage("Response", "Alerts");
  const { data, error, reload } = useV1<AlertRow[]>("alerts", { limit: 200 });
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      {me?.role === "admin" && <AdminRules />}
      <Card className="!p-0">
        <div className="p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Recent alerts" sub="Within your clearance; what was sent where" />
        </div>
        {error && !data ? (
          <Failed error={error} onRetry={reload} />
        ) : !data ? (
          <Skeleton className="mx-6 mb-6 h-24" />
        ) : !data.length ? (
          <Empty>No alerts yet.</Empty>
        ) : (
          <ul className="divide-y divide-line border-t border-line">
            {data.map((a) => (
              <li key={a.id} className="grid gap-2 px-5 py-3 sm:grid-cols-[1fr_auto] sm:px-6">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2 text-[12px] text-ink-muted">
                    <BellRing className="h-3.5 w-3.5" /> {a.rule} · {ago(a.createdAt)} <TlpTag tlp={a.tlp} />
                  </p>
                  {a.link ? (
                    <Link to={a.link} className="font-medium hover:text-accent-soft">{a.title}</Link>
                  ) : (
                    <p className="font-medium">{a.title}</p>
                  )}
                  <ul className="text-[12.5px] text-ink-muted">
                    {a.lines.map((l, i) => (
                      <li key={i} className="break-words">{l}</li>
                    ))}
                  </ul>
                </div>
                <ul className="text-right text-[12px]">
                  {Object.entries(a.delivered).map(([ch, st]) => (
                    <li key={ch} className={st === "sent" ? "text-up" : st.startsWith("held") ? "text-warn" : "text-down"}>
                      #{ch}: {st}
                    </li>
                  ))}
                </ul>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
