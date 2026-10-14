import { Download, Loader2, Lock, Plus, Save, Trash2, Unlock } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Ioc, Score, TlpTag, VerdictPill } from "../components/intel";
import { SevPill } from "../components/recon";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { send, useV1, type CaseDetail, type CaseItem, type Me } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { defang } from "../lib/ioc";
import { usePage } from "../lib/page";

function Item({ it, canEdit, onRemove }: { it: CaseItem; canEdit: boolean; onRemove: () => void }) {
  const snap = it.snapshot as { verdict?: string; priority?: number; sources?: string[]; indicator_id?: number };
  const href = it.kind === "indicator" && snap.indicator_id ? `/indicators/${snap.indicator_id}` : it.kind === "vulnerability" ? `/ui/vulnerabilities/${encodeURIComponent(it.ref)}` : null;
  return (
    <li className="flex flex-wrap items-start gap-3 px-5 py-4 sm:px-6">
      <span className="w-24 shrink-0 pt-0.5 text-[11.5px] uppercase tracking-wide text-ink-faint">{it.kind}</span>
      <div className="min-w-0 flex-1">
        {it.kind === "note" ? (
          <p className="whitespace-pre-wrap text-[13.5px]">{defang(it.note)}</p>
        ) : (
          <>
            <p className="flex flex-wrap items-center gap-2">
              {href && !href.startsWith("/ui") ? (
                <Link to={href} className="hover:text-accent-soft">
                  <Ioc value={it.label} className="text-[13.5px]" />
                </Link>
              ) : href ? (
                <a href={href} className="hover:text-accent-soft"><Ioc value={it.label} className="text-[13.5px]" /></a>
              ) : (
                <Ioc value={it.label} className="text-[13.5px]" />
              )}
              {snap.verdict && <VerdictPill verdict={snap.verdict} />}
              {snap.priority != null && <Score n={snap.priority} />}
              <TlpTag tlp={it.tlp} />
            </p>
            {it.note && <p className="mt-1 text-[13px] text-ink-muted">{defang(it.note)}</p>}
            {snap.sources?.length ? <p className="mt-1 text-[12px] text-ink-faint">reported by {snap.sources.join(", ")}</p> : null}
          </>
        )}
        <p className="mt-1 text-[12px] text-ink-faint">
          added by {it.added_by} {ago(it.added_at)}
        </p>
      </div>
      {canEdit && (
        <button className="btn-ghost h-8 w-8 !px-0 hover:!text-down" onClick={onRemove} aria-label="Remove from case" title="Remove from case">
          <Trash2 className="h-4 w-4" />
        </button>
      )}
    </li>
  );
}

export default function CaseView({ me }: { me?: Me }) {
  const { id = "" } = useParams();
  const { data: c, error, reload } = useV1<CaseDetail>(`cases/${id}`);
  usePage("Response", "Cases", c ? `#${c.id}` : "Case");
  const [summary, setSummary] = useState("");
  const [conclusion, setConclusion] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [values, setValues] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>();
  const canEdit = (me?.role === "admin" || me?.role === "analyst") && c?.status === "open";

  useEffect(() => {
    if (c) {
      setSummary(c.summary);
      setConclusion(c.conclusion);
      setSeverity(c.severity);
    }
  }, [c]);

  const run = async (key: string, fn: () => Promise<unknown>, ok: string) => {
    setBusy(key);
    setMsg(undefined);
    try {
      await fn();
      setMsg({ ok: true, text: ok });
      reload();
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(undefined);
    }
  };

  if (error && !c) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Failed error={error} onRetry={reload} />
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        {!c ? (
          <Skeleton className="h-20" />
        ) : (
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-muted">
                <span>Case #{c.id}</span> <SevPill sev={c.severity} /> <TlpTag tlp={c.tlp} />
                <span className={c.status === "open" ? "text-up" : "text-ink-faint"}>{c.status === "open" ? "Open" : `Closed ${ago(c.closed_at)}`}</span>
              </p>
              <h1 className="text-[22px] font-semibold">{c.title}</h1>
              <p className="mt-1 text-[13px] text-ink-muted">
                Opened by {c.created_by} {dateTime(c.created_at)} · {c.items} item{c.items === 1 ? "" : "s"}
              </p>
            </div>
            <div className="flex flex-wrap gap-2">
              <a className="btn-ghost h-9" href={`/api/v1/cases/${c.id}/export.md`}>
                <Download className="h-4 w-4" /> Report (Markdown)
              </a>
              {(me?.role === "admin" || me?.role === "analyst") && (
                <button
                  className="btn-ghost h-9"
                  disabled={!!busy}
                  onClick={() => run("status", () => send("PATCH", `/api/v1/cases/${c.id}`, { status: c.status === "open" ? "closed" : "open" }), c.status === "open" ? "Case closed" : "Case reopened")}
                >
                  {c.status === "open" ? <Lock className="h-4 w-4" /> : <Unlock className="h-4 w-4" />} {c.status === "open" ? "Close case" : "Reopen"}
                </button>
              )}
            </div>
          </div>
        )}
        {msg && <p className={`mt-3 text-[13px] ${msg.ok ? "text-up" : "text-down"}`}>{msg.text}</p>}
      </Card>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Evidence" sub="Snapshots taken when each item was added, so the case reads the same later" />
          </div>
          {!c ? (
            <Skeleton className="mx-6 mb-6 h-24" />
          ) : !c.evidence.length ? (
            <Empty>No evidence yet.</Empty>
          ) : (
            <ul className="divide-y divide-line/70 border-t border-line">
              {c.evidence.map((it) => (
                <Item key={it.id} it={it} canEdit={!!canEdit} onRemove={() => run(`rm${it.id}`, () => send("DELETE", `/api/v1/cases/${c.id}/items/${it.id}`), "Removed")} />
              ))}
            </ul>
          )}
          {canEdit && c && (
            <div className="grid gap-4 border-t border-line p-5 sm:grid-cols-2 sm:p-6">
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run("values", () => send("POST", `/api/v1/cases/${c.id}/items`, { values: values.split(/[\s,]+/).filter(Boolean) }), "Added").then(() => setValues(""));
                }}
              >
                <span className="label block">Add indicators (looked up as they are added)</span>
                <textarea value={values} onChange={(e) => setValues(e.target.value)} rows={3} className="ctl h-auto w-full py-2 font-mono text-[13px]" placeholder="IPs, domains, URLs, hashes" />
                <button className="btn-ghost h-9" disabled={!values.trim() || !!busy}>
                  {busy === "values" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add values
                </button>
              </form>
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run("note", () => send("POST", `/api/v1/cases/${c.id}/items`, { kind: "note", note }), "Note added").then(() => setNote(""));
                }}
              >
                <span className="label block">Add a note</span>
                <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3} className="ctl h-auto w-full py-2" placeholder="Timeline, findings, decisions" />
                <button className="btn-ghost h-9" disabled={!note.trim() || !!busy}>
                  <Plus className="h-4 w-4" /> Add note
                </button>
              </form>
            </div>
          )}
        </Card>

        <Card>
          <CardHead title="Write-up" sub={canEdit ? "Saved with the case and in its report" : "Read only"} />
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              if (c) void run("save", () => send("PATCH", `/api/v1/cases/${c.id}`, { summary, conclusion, severity }), "Saved");
            }}
          >
            <fieldset disabled={!canEdit} className="space-y-3">
              <label className="block">
                <span className="label mb-1 block">Severity</span>
                <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="ctl w-full">
                  {["low", "medium", "high", "critical"].map((s) => (
                    <option key={s}>{s}</option>
                  ))}
                </select>
              </label>
              <label className="block">
                <span className="label mb-1 block">Summary</span>
                <textarea value={summary} onChange={(e) => setSummary(e.target.value)} rows={6} className="ctl h-auto w-full py-2" />
              </label>
              <label className="block">
                <span className="label mb-1 block">Conclusion</span>
                <textarea value={conclusion} onChange={(e) => setConclusion(e.target.value)} rows={4} className="ctl h-auto w-full py-2" placeholder="Root cause, impact, what was done" />
              </label>
            </fieldset>
            {canEdit && (
              <button className="btn-primary" disabled={busy === "save"}>
                {busy === "save" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save
              </button>
            )}
          </form>
        </Card>
      </div>
    </div>
  );
}
