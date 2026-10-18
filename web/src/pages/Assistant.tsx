import { AlertTriangle, Check, FileSearch, Loader2, Sparkles, X } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Ioc, TlpTag } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { send, useV1, type Me } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

interface Status {
  enabled: boolean;
  model: string | null;
  maxTlp: string;
}

interface DraftIoc {
  type: string;
  value: string;
  defanged: string;
  context: string;
}

interface Draft {
  id: number;
  title: string;
  tlp: string;
  status: "draft" | "approved" | "rejected";
  actor: string;
  model: string;
  createdAt: string;
  reviewedBy: string | null;
  counts: { iocs: number; ttps: number; rejected: number };
  case: number | null;
  fingerprints: { source: string; prompt: string; output: string };
  result?: {
    summary: string;
    iocs: DraftIoc[];
    ttps: { technique: string; name: string; evidence: string }[];
    actors: string[];
    malware: string[];
    warnings: string[];
    servedBy?: string;
  };
  rejected?: { kind: string; value?: string; technique?: string; reason: string }[];
}

const LEVELS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT"];

function DraftView({ d, analyst, onDone }: { d: Draft; analyst: boolean; onDone: (d: Draft) => void }) {
  const res = d.result!;
  const [keep, setKeep] = useState<number[]>(res.iocs.map((_, i) => i));
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  useEffect(() => setKeep(res.iocs.map((_, i) => i)), [d.id, res.iocs]);
  const review = async (decision: "approve" | "reject") => {
    setBusy(decision);
    setError(undefined);
    try {
      onDone(await send<Draft>("POST", `/api/v1/ai/drafts/${d.id}/review`, { decision, keep }));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  return (
    <Card>
      <CardHead title={`Draft #${d.id}: ${d.title}`} sub={`${d.status} · by ${d.actor} ${ago(d.createdAt)} · answered by ${res.servedBy ?? d.model}`}>
        <TlpTag tlp={d.tlp} />
      </CardHead>
      {res.warnings.map((w) => (
        <p key={w} role="alert" className="mb-3 flex items-start gap-2 rounded-ctl border border-warn/40 bg-warn/10 p-3 text-[13px]">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" /> {w} Values that appear only in those sentences were refused.
        </p>
      ))}
      {res.summary && <p className="mb-4 text-[14px]">{res.summary}</p>}
      <div className="grid gap-6 lg:grid-cols-2">
        <section>
          <h3 className="label mb-2">Indicators ({res.iocs.length}), each found in the report</h3>
          {!res.iocs.length ? (
            <p className="text-[13px] text-ink-muted">None accepted.</p>
          ) : (
            <ul className="divide-y divide-line rounded-ctl border border-line text-[13px]">
              {res.iocs.map((x, i) => (
                <li key={x.type + x.value} className="flex items-start gap-2 px-3 py-2">
                  {d.status === "draft" && analyst && (
                    <input type="checkbox" className="mt-1 h-4 w-4 accent-accent" checked={keep.includes(i)} aria-label={`Keep ${x.defanged}`}
                      onChange={(e) => setKeep(e.target.checked ? [...keep, i] : keep.filter((k) => k !== i))} />
                  )}
                  <span className="min-w-0">
                    <Ioc value={x.defanged} /> <span className="text-ink-faint">{x.type}</span>
                    {x.context && <span className="block text-[12px] text-ink-muted">{x.context}</span>}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h3 className="label mb-2">Techniques ({res.ttps.length}), each with a quotation from the report</h3>
          {!res.ttps.length ? (
            <p className="text-[13px] text-ink-muted">None accepted.</p>
          ) : (
            <ul className="space-y-2 text-[13px]">
              {res.ttps.map((t) => (
                <li key={t.technique}>
                  <span className="font-mono">{t.technique}</span> {t.name} <span className="block text-[12px] text-ink-muted">“{t.evidence}”</span>
                </li>
              ))}
            </ul>
          )}
          {(res.actors.length > 0 || res.malware.length > 0) && (
            <p className="mt-3 text-[13px]">
              {res.actors.length > 0 && <>Actors: <b>{res.actors.join(", ")}</b>. </>}
              {res.malware.length > 0 && <>Malware: <b>{res.malware.join(", ")}</b>.</>}
            </p>
          )}
        </section>
      </div>
      {!!d.rejected?.length && (
        <details className="mt-4 text-[13px]">
          <summary className="cursor-pointer text-ink-muted">Refused by validation ({d.rejected.length})</summary>
          <ul className="mt-2 space-y-1">
            {d.rejected.map((r, i) => (
              <li key={i}>
                <span className="text-ink-faint">{r.kind}</span> <span className="font-mono break-all">{r.technique ?? r.value}</span>: {r.reason}
              </li>
            ))}
          </ul>
        </details>
      )}
      <p className="mt-4 text-[11.5px] text-ink-faint">
        Fingerprints: report <span className="font-mono">{d.fingerprints.source.slice(0, 16)}</span> · prompt <span className="font-mono">{d.fingerprints.prompt.slice(0, 16)}</span> · answer{" "}
        <span className="font-mono">{d.fingerprints.output.slice(0, 16)}</span>
      </p>
      {error && <p role="alert" className="mt-3 text-[13px] text-down">{error}</p>}
      {d.status === "draft" && analyst ? (
        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <button className="btn-ghost h-9" disabled={!!busy} onClick={() => review("reject")}>
            {busy === "reject" ? <Loader2 className="h-4 w-4 animate-spin" /> : <X className="h-4 w-4" />} Reject
          </button>
          <button className="btn-primary h-9" disabled={!!busy} onClick={() => review("approve")}>
            {busy === "approve" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Approve into a case ({keep.length} indicators)
          </button>
        </div>
      ) : d.case ? (
        <p className="mt-4 text-[13px]">
          Approved by {d.reviewedBy} into <Link className="underline" to={`/cases/${d.case}`}>case #{d.case}</Link>.
        </p>
      ) : null}
    </Card>
  );
}

export default function Assistant({ me }: { me?: Me }) {
  usePage("Threat intel", "Report assistant");
  const status = useV1<Status>("ai/status");
  const drafts = useV1<Draft[]>("ai/drafts");
  const [title, setTitle] = useState("");
  const [text, setText] = useState("");
  const [tlp, setTlp] = useState("TLP:CLEAR");
  const [busy, setBusy] = useState<string>();
  const [error, setError] = useState<string>();
  const [draft, setDraft] = useState<Draft>();
  const [plain, setPlain] = useState<{ iocs: { type: string; defanged: string }[]; warnings: string[] }>();
  const analyst = me?.role === "admin" || me?.role === "analyst";
  const allowed = status.data ? LEVELS.slice(0, LEVELS.indexOf(status.data.maxTlp) + 1) : ["TLP:CLEAR"];

  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("ai");
    setError(undefined);
    try {
      setDraft(await send<Draft>("POST", "/api/v1/ai/extract", { title, text, tlp }));
      drafts.reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const extractOnly = async () => {
    setBusy("plain");
    setError(undefined);
    try {
      setPlain(await send("POST", "/api/v1/ai/deterministic", { text }));
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const open = async (id: number) => {
    setError(undefined);
    try {
      const r = await fetch(`/api/v1/ai/drafts/${id}`, { credentials: "same-origin", headers: { Accept: "application/json" } });
      if (!r.ok) throw new Error(`${r.status} error`);
      setDraft(await r.json());
    } catch (err) {
      setError((err as Error).message);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead
          title="Report assistant"
          sub="Paste a threat report. A language model drafts the summary, attacker indicators, ATT&CK techniques and names; every item is checked against the report text, and nothing is used until an analyst approves the draft. The report is treated as untrusted: instructions inside it are ignored and flagged."
        >
          {status.data && (
            <span className={`text-[12px] ${status.data.enabled ? "text-up" : "text-ink-muted"}`}>
              {status.data.enabled ? `${status.data.model} · up to ${status.data.maxTlp}` : "AI off: extractor only"}
            </span>
          )}
        </CardHead>
        {status.data && !status.data.enabled && (
          <p className="mb-3 text-[13px] text-ink-muted">
            The AI assistant is off. An administrator can enable it with TL_AI_ENABLED=true and a Claude API key (TL_AI_API_KEY); report text is then sent to Anthropic's API.
            Meanwhile, the extractor below finds every indicator in the text without a model (it can't tell attacker infrastructure from benign mentions).
          </p>
        )}
        <form onSubmit={run} className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
            <input className="ctl w-full" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Report title, e.g. vendor advisory name" maxLength={300} aria-label="Title" />
            <label className="inline-flex items-center gap-2">
              <span className="label">Marking</span>
              <select className="ctl h-9 text-[13px]" value={tlp} onChange={(e) => setTlp(e.target.value)}>
                {allowed.map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
          </div>
          <textarea className="ctl min-h-[220px] w-full font-mono text-[12.5px]" value={text} onChange={(e) => setText(e.target.value)} placeholder="Paste the report text here" maxLength={200000} aria-label="Report text" />
          <div className="flex flex-wrap justify-end gap-2">
            <button type="button" className="btn-ghost h-9" disabled={!!busy || !text.trim()} onClick={extractOnly}>
              {busy === "plain" ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileSearch className="h-4 w-4" />} Extract without AI
            </button>
            {analyst && status.data?.enabled && (
              <button className="btn-primary h-9" disabled={!!busy || !text.trim() || title.trim().length < 2}>
                {busy === "ai" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />} Draft with AI
              </button>
            )}
          </div>
          {error && <p role="alert" className="text-[13px] text-down">{error}</p>}
        </form>
        {plain && (
          <div className="mt-4 text-[13px]">
            <p className="label mb-2">Extractor: {plain.iocs.length} value(s) in the text</p>
            {plain.warnings.length > 0 && <p className="mb-2 text-warn">The text contains instructions aimed at a model: {plain.warnings.join("; ")}</p>}
            <ul className="flex flex-wrap gap-x-4 gap-y-1">
              {plain.iocs.map((x) => (
                <li key={x.type + x.defanged}>
                  <Ioc value={x.defanged} /> <span className="text-ink-faint">{x.type}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </Card>
      {draft?.result && <DraftView d={draft} analyst={analyst} onDone={(d) => { setDraft(d); drafts.reload(); }} />}
      <Card className="!p-0">
        <div className="p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Drafts" sub="Within your clearance" />
        </div>
        {drafts.error && !drafts.data ? (
          <Failed error={drafts.error} onRetry={drafts.reload} />
        ) : !drafts.data ? (
          <Skeleton className="mx-6 mb-6 h-16" />
        ) : !drafts.data.length ? (
          <Empty>No drafts yet.</Empty>
        ) : (
          <ul className="divide-y divide-line border-t border-line">
            {drafts.data.map((d) => (
              <li key={d.id} className="flex flex-wrap items-center gap-3 px-5 py-2.5 text-[13px] sm:px-6">
                <button className="min-w-0 flex-1 text-left hover:text-accent-soft" onClick={() => open(d.id)}>
                  <b>#{d.id} {d.title}</b>{" "}
                  <span className="text-ink-muted">
                    · {d.status} · {d.counts.iocs} indicators, {d.counts.ttps} techniques, {d.counts.rejected} refused · {ago(d.createdAt)}
                  </span>
                </button>
                <TlpTag tlp={d.tlp} />
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
