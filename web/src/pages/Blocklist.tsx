import { CheckCheck, Clock, Loader2, Search, ShieldBan, ShieldCheck, Undo2, X } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { Ioc, Score, TlpTag } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { post, send, useApi, useDebounced, useV1, type Block, type Me } from "../lib/api";
import { ago, dateTime } from "../lib/format";
import { usePage } from "../lib/page";

const VIEWS = ["Live", "Enforced", "Monitor", "Awaiting approval", "Expired", "Lifted", "All"] as const;
const VIEW_KEY: Record<(typeof VIEWS)[number], string> = { Live: "live", Enforced: "enforce", Monitor: "monitor", "Awaiting approval": "pending", Expired: "expired", Lifted: "lifted", All: "all" };
const STATE: Record<string, [string, string]> = {
  enforce: ["Enforced", "bg-down/12 text-down ring-down/25"],
  monitor: ["Monitor", "bg-accent/10 text-accent-soft ring-accent/20"],
  pending: ["Awaiting approval", "bg-warn/10 text-warn ring-warn/25"],
  expired: ["Expired", "bg-ink-faint/15 text-ink-muted ring-line"],
  lifted: ["Lifted", "bg-ink-faint/15 text-ink-muted ring-line"],
};
const REASON: Record<string, string> = { known_bad: "Known bad", suspect: "Suspect", manual: "Manual" };

interface Counts {
  counts: Record<string, number>;
  requireSecondApprover: boolean;
  policy: Record<string, number>;
}

export default function Blocklist({ me }: { me?: Me }) {
  usePage("Response", "Blocklist");
  const [view, setView] = useState<(typeof VIEWS)[number]>("Live");
  const [q, setQ] = useState("");
  const search = useDebounced(q);
  const counts = useApi<Counts>("blocks/counts");
  const list = useV1<{ items: Block[]; total: number }>("blocks", { view: VIEW_KEY[view], q: search.trim() || undefined, limit: 200 });
  const [values, setValues] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState<string>();
  const [result, setResult] = useState<{ made: number; refused: string[] }>();
  const [error, setError] = useState<string>();
  const analyst = me?.role === "admin" || me?.role === "analyst";
  const admin = me?.role === "admin";

  const refresh = () => {
    list.reload();
    counts.reload();
  };

  const act = async (b: Block, action: string) => {
    setBusy(`${b.id}:${action}`);
    setError(undefined);
    try {
      if (action === "request-enforce" || action === "approve") await send("POST", `/api/v1/blocks/${b.id}/${action}`);
      else if (action === "lift") await send("POST", `/api/v1/blocks/${b.id}/lift`, { note: "" });
      else if (action === "extend") await post(`blocks/${b.id}/extend`, { days: 30 });
      else if (action === "decline") await post(`blocks/${b.id}/decline`);
      refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  const add = async (e: FormEvent) => {
    e.preventDefault();
    const vs = values.split(/[\s,]+/).map((v) => v.trim()).filter(Boolean);
    setBusy("add");
    setResult(undefined);
    let made = 0;
    const refused: string[] = [];
    for (const v of vs.slice(0, 500)) {
      try {
        await send("POST", "/api/v1/blocks", { value: v, note });
        made += 1;
      } catch (err) {
        refused.push((err as Error).message);
      }
    }
    setResult({ made, refused });
    setBusy(undefined);
    if (made) {
      setValues("");
      refresh();
    }
  };

  const c = counts.data?.counts ?? {};
  const tiles: [string, string, string, (typeof VIEWS)[number]][] = [
    ["Enforced", String(c.enforce ?? 0), "published to your firewalls", "Enforced"],
    ["Monitor", String(c.monitor ?? 0), "dry run, recorded only", "Monitor"],
    ["Awaiting approval", String(c.pending ?? 0), counts.data?.requireSecondApprover ? "a second admin approves" : "any admin enforces", "Awaiting approval"],
    ["Expiring in 24 h", String(c.expiring ?? 0), "extend to keep them", "Live"],
    ["Lifted", String(c.lifted ?? 0), "ended early, kept for history", "Lifted"],
  ];

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <div className="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        {tiles.map(([label, value, hint, v]) => (
          <button key={label} onClick={() => setView(v)} className={`card p-4 text-left transition-colors hover:border-accent/40 ${view === v && label !== "Expiring in 24 h" ? "border-accent/50" : ""}`}>
            <p className="label">{label}</p>
            <p className="mt-1.5 text-[26px] font-bold tabular-nums">{counts.data ? value : "–"}</p>
            <p className="text-[12px] text-ink-faint">{hint}</p>
          </button>
        ))}
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,8fr)_minmax(0,4fr)]">
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Blocks" sub="A block starts in monitor (recorded only). Enforced blocks are published to your firewalls through the feed export. Every block expires.">
              <Link to="/settings" className="btn-ghost h-8 text-[13px]">
                Policy and export
              </Link>
            </CardHead>
            <div className="flex flex-wrap items-center gap-3">
              <Segmented value={view} options={VIEWS} onChange={setView} label="Which blocks" />
              <label className="relative ml-auto w-full sm:w-60">
                <span className="sr-only">Filter</span>
                <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
                <input value={q} onChange={(e) => setQ(e.target.value)} className="ctl h-8 w-full pl-9 text-[13px]" placeholder="Value or note" />
              </label>
            </div>
          </div>
          {error && <p className="px-6 pb-2 text-[13px] text-down">{error}</p>}
          <div className="overflow-x-auto">
            <table className="w-full min-w-[860px] text-left text-[13.5px]">
              <thead>
                <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                  <th className="py-3 pl-6 font-medium">Value</th>
                  <th className="py-3 font-medium">State</th>
                  <th className="py-3 text-right font-medium">Score</th>
                  <th className="py-3 pl-6 font-medium">Why</th>
                  <th className="py-3 font-medium">Expires</th>
                  <th className="py-3 pr-6 text-right font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {!list.data && !list.error &&
                  Array.from({ length: 5 }, (_, i) => (
                    <tr key={i}>
                      <td colSpan={6} className="px-6 py-3">
                        <Skeleton className="h-6" />
                      </td>
                    </tr>
                  ))}
                {list.data?.items.map((b) => {
                  const [label, tone] = STATE[b.state] ?? [b.state, "bg-ink-faint/15 text-ink-muted ring-line"];
                  const live = b.state === "enforce" || b.state === "monitor" || b.state === "pending";
                  return (
                    <tr key={b.id} id={`block-${b.id}`} className="border-b border-line/70 odd:bg-white/[0.012] hover:bg-accent/[0.06]">
                      <td className="max-w-[300px] py-3 pl-6 pr-4">
                        <Ioc value={b.value} className="text-[13px]" />
                        <span className="mt-0.5 flex items-center gap-2 text-[12px] text-ink-faint">
                          {b.kind} <TlpTag tlp={b.tlp} />
                        </span>
                      </td>
                      <td className="py-3">
                        <span className={`inline-flex whitespace-nowrap rounded-full px-2.5 py-0.5 text-[12px] font-medium ring-1 ${tone}`}>{label}</span>
                        {b.requested_by && b.state === "pending" && <span className="mt-0.5 block text-[11.5px] text-ink-faint">asked by {b.requested_by}</span>}
                      </td>
                      <td className="py-3 text-right">
                        <Score n={b.score} />
                      </td>
                      <td className="max-w-[220px] py-3 pl-6">
                        <span className="text-ink">{REASON[b.reason] ?? b.reason}</span>
                        <span className="block truncate text-[12px] text-ink-faint" title={b.note}>
                          {b.created_by} {ago(b.created_at)}
                          {b.note && ` · ${b.note}`}
                        </span>
                      </td>
                      <td className="whitespace-nowrap py-3 text-ink-muted" title={dateTime(b.expires_at)}>
                        {b.lifted_at ? `lifted ${ago(b.lifted_at)}` : ago(b.expires_at)}
                      </td>
                      <td className="py-3 pr-6">
                        {analyst && live && (
                          <div className="flex justify-end gap-1.5">
                            {b.state === "monitor" && (
                              <button className="btn-ghost h-8 text-[12.5px]" disabled={!!busy} onClick={() => act(b, "request-enforce")} title="Publish it to firewalls (needs approval)">
                                {busy === `${b.id}:request-enforce` ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldBan className="h-3.5 w-3.5" />} Enforce
                              </button>
                            )}
                            {b.state === "pending" && admin && (
                              <button className="btn-ghost h-8 text-[12.5px] hover:!text-up" disabled={!!busy} onClick={() => act(b, "approve")}>
                                <CheckCheck className="h-3.5 w-3.5" /> Approve
                              </button>
                            )}
                            {b.state === "pending" && (
                              <button className="btn-ghost h-8 text-[12.5px]" disabled={!!busy} onClick={() => act(b, "decline")}>
                                <X className="h-3.5 w-3.5" /> Decline
                              </button>
                            )}
                            <button className="btn-ghost h-8 w-8 !px-0" title="Extend by 30 days" aria-label="Extend by 30 days" disabled={!!busy} onClick={() => act(b, "extend")}>
                              <Clock className="h-3.5 w-3.5" />
                            </button>
                            <button className="btn-ghost h-8 w-8 !px-0 hover:!text-down" title="Lift (end it now)" aria-label="Lift" disabled={!!busy} onClick={() => act(b, "lift")}>
                              <Undo2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            {list.error && !list.data && <Failed error={list.error} onRetry={list.reload} />}
            {list.data && !list.data.items.length && <Empty>No blocks here.</Empty>}
          </div>
        </Card>

        <div className="space-y-6">
          <Card>
            <CardHead title="Block now" sub="IPs, CIDR ranges, domains or URLs, one per line. Each is checked against your own assets and the never-block list first." />
            <form onSubmit={add} className="space-y-3">
              <textarea value={values} onChange={(e) => setValues(e.target.value)} rows={5} className="ctl h-auto w-full py-2 font-mono text-[13px]" placeholder={"203.0.113[.]7\nbad-domain[.]example"} disabled={!analyst} />
              <input value={note} onChange={(e) => setNote(e.target.value)} className="ctl w-full" placeholder="Why (ticket, alert, case)" maxLength={500} disabled={!analyst} />
              <button className="btn-primary w-full" disabled={!analyst || !values.trim() || busy === "add"}>
                {busy === "add" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldBan className="h-4 w-4" />} Block in monitor mode
              </button>
              {!analyst && <p className="text-[12.5px] text-ink-muted">Blocking needs the analyst role.</p>}
              {result && (
                <p className="text-[12.5px] text-ink-muted">
                  <b className="text-up">{result.made} blocked</b>
                  {result.refused.length > 0 && (
                    <>
                      , <b className="text-down">{result.refused.length} refused</b>: {result.refused.slice(0, 3).join("; ")}
                    </>
                  )}
                </p>
              )}
            </form>
          </Card>
          <Card>
            <CardHead title="How blocking works" />
            <ul className="space-y-2 text-[13px] text-ink-muted">
              <li className="flex gap-2"><ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-up" /> Your own assets, private ranges, public DNS resolvers and the never-block list can't be blocked, checked again on every export.</li>
              <li className="flex gap-2"><ShieldBan className="mt-0.5 h-4 w-4 shrink-0 text-accent-soft" /> Known bad: {counts.data?.policy.known_bad_days ?? "?"} days · suspect: {counts.data?.policy.suspect_days ?? "?"} days · manual: {counts.data?.policy.manual_days ?? "?"} days.</li>
              <li className="flex gap-2"><CheckCheck className="mt-0.5 h-4 w-4 shrink-0 text-warn" /> {counts.data?.requireSecondApprover ? "Enforcing needs a second admin's approval." : "An admin can enforce directly."}</li>
            </ul>
          </Card>
        </div>
      </div>
    </div>
  );
}
