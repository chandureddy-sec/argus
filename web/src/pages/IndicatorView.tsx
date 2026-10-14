import { Crosshair, Loader2, MessageSquare, RotateCcw } from "lucide-react";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { AddToCase, BlockButton } from "../components/actions";
import { CopyButton, Ioc, Score, StatusPill, TlpTag, VerdictPill } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { send, useV1, type IndicatorDetail, type Me } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { BLOCKABLE, defang, TYPE_LABEL, verdictOf } from "../lib/ioc";
import { usePage } from "../lib/page";

function Breakdown({ ind }: { ind: IndicatorDetail }) {
  const bd = ind.score_breakdown;
  if (!bd) return <Empty>Not scored yet.</Empty>;
  const patch = bd as unknown as { model?: string; priority?: string; note?: string };
  if (patch.model === "patch-priority") {
    return (
      <div className="space-y-3">
        <p className="text-[14px]">
          Scored by <b>patch priority</b>: <span className="rounded bg-down/15 px-2 py-0.5 font-semibold text-down">{patch.priority}</span>
        </p>
        <p className="text-[13px] text-ink-muted">{patch.note}. Patch priority weighs exploitation in the wild (KEV), exploit likelihood (EPSS), severity and whether your own software is affected.</p>
        <a href={`/ui/vulnerabilities/${encodeURIComponent(ind.value)}`} className="btn-ghost h-9">Open the vulnerability</a>
      </div>
    );
  }
  const parts: [string, number | undefined, string][] = [
    ["Strongest report", bd.base?.value, bd.base?.source ? `from ${bd.base.source}` : "no report"],
    ["Corroboration", bd.corroboration?.value, bd.corroboration?.upstreams?.length ? `also: ${bd.corroboration.upstreams.join(", ")}` : "no other independent source"],
    ["Relevance to you", bd.relevance?.value, bd.relevance?.hits?.map((h) => h.reason).join("; ") || "no match with your assets or priorities"],
    ["False-positive signs", bd.penalty?.value ? -bd.penalty.value : 0, bd.penalty?.items?.map((p) => p.reason).join("; ") || "none"],
  ];
  return (
    <div className="space-y-5">
      {bd.suppressed && <p className="rounded-ctl border border-up/30 bg-up/[0.06] px-3 py-2 text-[13px] text-up">Score 0: {bd.suppressed}</p>}
      <dl className="grid gap-3 sm:grid-cols-2">
        {parts.map(([label, v, why]) => (
          <div key={label} className="rounded-ctl border border-line bg-card-2/40 p-3.5">
            <dt className="flex items-center justify-between text-[13px] text-ink-muted">
              {label}
              <b className={`tabular-nums ${(v ?? 0) < 0 ? "text-up" : (v ?? 0) > 0 ? "text-ink" : "text-ink-faint"}`}>
                {(v ?? 0) > 0 ? "+" : ""}
                {(v ?? 0).toFixed(1)}
              </b>
            </dt>
            <dd className="mt-1 text-[12.5px] text-ink-faint">{why}</dd>
          </div>
        ))}
      </dl>
      {bd.formula && <p className="font-mono text-[12.5px] text-ink-muted">score = {bd.formula}</p>}
      {bd.signals?.length ? (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-[13px]">
            <thead>
              <tr className="border-b border-line text-[11.5px] uppercase tracking-wide text-ink-faint">
                <th className="py-2 font-medium">Signal</th>
                <th className="py-2 text-right font-medium">Confidence</th>
                <th className="py-2 text-right font-medium">Weight</th>
                <th className="py-2 text-right font-medium">Freshness</th>
                <th className="py-2 text-right font-medium">Counts</th>
              </tr>
            </thead>
            <tbody>
              {bd.signals.map((s, i) => (
                <tr key={i} className="border-b border-line/60">
                  <td className="py-2">
                    <span className={s.kind === "malicious" ? "text-down" : s.kind === "suspicious" ? "text-warn" : "text-up"}>{s.kind}</span>{" "}
                    <span className="text-ink-muted">{defang(s.text)}</span>
                  </td>
                  <td className="py-2 text-right tabular-nums">{s.confidence}</td>
                  <td className="py-2 text-right tabular-nums">×{s.weight.toFixed(2)}</td>
                  <td className="py-2 text-right tabular-nums" title={`${s.age_days.toFixed(1)} days old`}>×{s.decay.toFixed(2)}</td>
                  <td className={`py-2 text-right font-semibold tabular-nums ${s.counted ? "text-ink" : "text-ink-faint line-through"}`}>{s.value.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}

function Notes({ id, canWrite }: { id: number; canWrite: boolean }) {
  const notes = useV1<{ id: number; author: string; body: string; created_at: string }[]>(`indicators/${id}/notes`);
  const [body, setBody] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  return (
    <div className="space-y-4">
      {notes.data?.length ? (
        <ul className="space-y-3">
          {notes.data.map((n) => (
            <li key={n.id} className="rounded-ctl border border-line bg-card-2/40 p-3">
              <p className="whitespace-pre-wrap text-[13.5px] text-ink">{defang(n.body)}</p>
              <p className="mt-1 text-[12px] text-ink-faint">
                {n.author} · {ago(n.created_at)}
              </p>
            </li>
          ))}
        </ul>
      ) : notes.data ? (
        <p className="text-[13px] text-ink-muted">No notes yet.</p>
      ) : (
        <Skeleton className="h-10" />
      )}
      {canWrite && (
        <form
          className="space-y-2"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError(undefined);
            try {
              await send("POST", `/api/v1/indicators/${id}/notes`, { body });
              setBody("");
              notes.reload();
            } catch (err) {
              setError((err as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={3} className="ctl h-auto w-full py-2" placeholder="What you found, where you saw it, what you did…" maxLength={5000} />
          <div className="flex items-center gap-3">
            <button className="btn-primary" disabled={!body.trim() || busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <MessageSquare className="h-4 w-4" />} Add note
            </button>
            {error && <span className="text-[12.5px] text-down">{error}</span>}
          </div>
        </form>
      )}
    </div>
  );
}

export default function IndicatorView({ me }: { me?: Me }) {
  const { id = "" } = useParams();
  const { data: ind, error, reload } = useV1<IndicatorDetail>(`indicators/${id}`);
  usePage("Threat intel", "Indicators", ind ? `#${ind.id}` : "Indicator");
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const analyst = me?.role === "admin" || me?.role === "analyst";

  const feedback = async (verdict: "tp" | "fp" | "reset") => {
    setBusy(verdict);
    setMsg(undefined);
    try {
      await send("POST", `/api/v1/indicators/${id}/feedback`, { verdict });
      reload();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  if (error && !ind) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Failed error={error.startsWith("404") ? "No such indicator, or it is above your clearance" : error} onRetry={reload} />
        </Card>
      </div>
    );
  }
  const verdict = ind?.status === "false_positive" ? "benign" : verdictOf(ind?.priority_score);

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        {!ind ? (
          <Skeleton className="h-24" />
        ) : (
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="min-w-0 flex-1">
              <p className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-muted">
                {TYPE_LABEL[ind.type] ?? ind.type} <TlpTag tlp={ind.tlp} /> <StatusPill status={ind.status} /> <VerdictPill verdict={verdict} />
              </p>
              <h1 className="text-[20px] font-semibold leading-snug">
                <Ioc value={ind.defanged} />
              </h1>
              <p className="mt-2 text-[13px] text-ink-muted">
                Reported by {ind.sources.join(", ") || "an analyst"} · first seen {dateTime(ind.first_seen)} · last seen {ago(ind.last_seen)}
                {ind.valid_until && <> · expires {ago(ind.valid_until)}</>}
              </p>
              {ind.labels.length > 0 && (
                <p className="mt-2 flex flex-wrap gap-1.5">
                  {ind.labels.map((l) => (
                    <span key={l} className="rounded bg-card-2 px-2 py-0.5 text-[12px] text-ink-muted ring-1 ring-line">
                      {l}
                    </span>
                  ))}
                </p>
              )}
            </div>
            <div className="text-right">
              <p className="label">Score</p>
              <p className={`text-[44px] font-bold leading-none tabular-nums ${verdict === "malicious" ? "text-down" : verdict === "suspicious" ? "text-warn" : "text-ink"}`}>
                {ind.priority_score != null ? Math.round(ind.priority_score) : "–"}
              </p>
              <Score n={ind.priority_score} wide />
            </div>
          </div>
        )}
        {ind && (
          <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-line pt-5">
            <CopyButton value={ind.defanged} label="Copy value" />
            <Link to={`/verify?q=${encodeURIComponent(ind.defanged)}`} className="btn-ghost h-9">
              <Crosshair className="h-4 w-4" /> Verify now
            </Link>
            {analyst && BLOCKABLE.has(ind.type) && <BlockButton value={ind.defanged} />}
            {analyst && <AddToCase indicatorId={ind.id} />}
            {analyst && (
              <span className="ml-auto inline-flex flex-wrap items-center gap-2">
                {ind.analyst_verdict ? (
                  <button className="btn-ghost h-9" disabled={!!busy} onClick={() => feedback("reset")}>
                    {busy === "reset" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCcw className="h-4 w-4" />} Undo analyst verdict
                  </button>
                ) : (
                  <>
                    <button className="btn-ghost h-9 hover:!text-down" disabled={!!busy} onClick={() => feedback("tp")}>
                      {busy === "tp" && <Loader2 className="h-4 w-4 animate-spin" />} Confirm malicious
                    </button>
                    <button className="btn-ghost h-9 hover:!text-up" disabled={!!busy} onClick={() => feedback("fp")}>
                      {busy === "fp" && <Loader2 className="h-4 w-4 animate-spin" />} Not malicious
                    </button>
                  </>
                )}
              </span>
            )}
            {msg && <span className="w-full text-[12.5px] text-down">{msg}</span>}
          </div>
        )}
      </Card>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <Card>
          <CardHead title="Why this score" sub="Every part of the 0–100 score, from the reports behind it" />
          {ind ? <Breakdown ind={ind} /> : <Skeleton className="h-40" />}
        </Card>
        <Card>
          <CardHead title="Analyst notes" sub={ind?.feedback.length ? `Decisions: ${ind.feedback.map((f) => `${f.verdict === "tp" ? "malicious" : f.verdict === "fp" ? "not malicious" : "reset"} by ${f.actor}`).join(", ")}` : "Shared with everyone who can see this indicator"} />
          {ind ? <Notes id={ind.id} canWrite={analyst} /> : <Skeleton className="h-24" />}
        </Card>
      </div>

      <Card className="!p-0">
        <div className="p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Reports" sub="Each source's report of this indicator, with the context it gave" />
        </div>
        {!ind ? (
          <Skeleton className="mx-6 mb-6 h-24" />
        ) : !ind.sightings.length ? (
          <Empty>No feed reports it: an analyst added it.</Empty>
        ) : (
          <ul className="divide-y divide-line/70 border-t border-line">
            {ind.sightings.map((s) => (
              <li key={s.source} className="grid gap-3 px-5 py-4 sm:grid-cols-[200px_1fr] sm:px-6">
                <div>
                  <p className="font-medium">{s.source}</p>
                  <p className="text-[12px] text-ink-faint">
                    {s.times_reported}× · confidence {s.confidence}
                    <br />
                    {dateTime(s.first_seen)} → {ago(s.last_seen)}
                  </p>
                </div>
                <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-[13px]">
                  {Object.entries(s.context)
                    .filter(([, v]) => v !== null && v !== "" && typeof v !== "object")
                    .slice(0, 12)
                    .map(([k, v]) => (
                      <div key={k} className="contents">
                        <dt className="text-ink-faint">{k.replace(/_/g, " ")}</dt>
                        <dd className="break-all text-ink-muted">{defang(String(v)).slice(0, 300)}</dd>
                      </div>
                    ))}
                </dl>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
