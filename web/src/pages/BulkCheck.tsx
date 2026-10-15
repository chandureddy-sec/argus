import { Download, FileUp, Loader2, ShieldBan, Square } from "lucide-react";
import { useMemo, useRef, useState, type FormEvent } from "react";
import { FlagButtons } from "../components/actions";
import { Ioc, Score, TlpSelect, VerdictPill } from "../components/intel";
import { Empty } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { readEvents, send, type BulkEvent, type BulkRow, type Me } from "../lib/api";
import { usePage } from "../lib/page";

const FILTERS = ["All", "Malicious", "Suspicious", "No known threat", "Clean"] as const;
const FILTER_VERDICT: Record<string, string> = { Malicious: "malicious", Suspicious: "suspicious", "No known threat": "unknown", Clean: "benign" };
const ORDER: Record<string, number> = { malicious: 0, suspicious: 1, unknown: 2, benign: 3 };
/** A CSV cell that a spreadsheet won't run as a formula (=, +, -, @ get a leading quote). */
export function csvCell(v: unknown): string {
  let s = v == null ? "" : String(v);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadCsv(rows: BulkRow[]) {
  const head = ["value_defanged", "type", "verdict", "score", "action", "sources", "country", "providers", "our_asset", "blocked"];
  const lines = rows.map((r) =>
    [r.query.value, r.query.type, r.verdict, r.score, r.action, r.sources.join(";"), r.country ?? "",
     r.signals.map((x) => `${x.name}:${x.kind}`).join(";"), r.asset ? "yes" : "", r.block ? r.block.mode : ""].map(csvCell).join(","),
  );
  const blob = new Blob([[head.join(","), ...lines].join("\r\n")], { type: "text/csv;charset=utf-8" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `bulk-check-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.csv`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

const SIG: Record<string, string> = { malicious: "bg-down/15 text-down", suspicious: "bg-warn/15 text-warn", benign: "bg-up/15 text-up", info: "bg-chip text-chip-ink" };

export default function BulkCheck({ me }: { me?: Me }) {
  usePage("Threat intel", "Bulk check");
  const [text, setText] = useState("");
  const [files, setFiles] = useState<File[]>([]);
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [providers, setProviders] = useState(false);
  const [autoblock, setAutoblock] = useState(false);
  const [rows, setRows] = useState<BulkRow[]>([]);
  const [progress, setProgress] = useState<[number, number]>();
  const [summary, setSummary] = useState<Extract<BulkEvent, { event: "done" }>>();
  const [notes, setNotes] = useState<string[]>([]);
  const [error, setError] = useState<string>();
  const [running, setRunning] = useState(false);
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("All");
  const [picked, setPicked] = useState<Set<string>>(new Set());
  const [blockMsg, setBlockMsg] = useState<string>();
  const abort = useRef<AbortController>();
  const analyst = me?.role === "admin" || me?.role === "analyst";

  const run = async (e: FormEvent) => {
    e.preventDefault();
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setRunning(true);
    setError(undefined);
    setRows([]);
    setSummary(undefined);
    setPicked(new Set());
    setBlockMsg(undefined);
    const form = new FormData();
    form.set("text", text);
    form.set("tlp", tlp);
    form.set("providers", String(providers));
    form.set("autoblock", String(autoblock));
    for (const f of files) form.append("files", f);
    try {
      const r = await fetch("/app/api/bulk/stream", { method: "POST", body: form, credentials: "same-origin", signal: ac.signal });
      await readEvents<BulkEvent>(r, (ev) => {
        if (ev.event === "start") {
          setProgress([0, ev.total]);
          setNotes(ev.notes);
        } else if (ev.event === "row") {
          setRows((xs) => [...xs, ev.row]);
          setProgress([ev.done, ev.total]);
          if (ev.row.verdict === "malicious" || ev.row.verdict === "suspicious") setPicked((p) => new Set(p).add(ev.row.query.value));
        } else if (ev.event === "skip") {
          setProgress([ev.done, ev.total]);
        } else {
          setSummary(ev);
        }
      });
    } catch (err) {
      if ((err as Error).name !== "AbortError") setError((err as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const counts = useMemo(() => rows.reduce<Record<string, number>>((a, r) => ({ ...a, [r.verdict]: (a[r.verdict] ?? 0) + 1 }), {}), [rows]);
  const shown = useMemo(
    () => [...rows].filter((r) => filter === "All" || r.verdict === FILTER_VERDICT[filter]).sort((a, b) => (ORDER[a.verdict] ?? 9) - (ORDER[b.verdict] ?? 9) || b.score - a.score),
    [rows, filter],
  );
  const pickedRows = rows.filter((r) => picked.has(r.query.value));
  const toggle = (v: string) => setPicked((p) => (p.has(v) ? (p.delete(v), new Set(p)) : new Set(p).add(v)));

  const blockPicked = async () => {
    const values = pickedRows.filter((r) => r.blockable && !r.block).map((r) => r.query.value);
    if (!values.length) return setBlockMsg("Nothing picked can be blocked (already blocked, or not an IP, domain or URL).");
    let made = 0;
    const why: string[] = [];
    for (const v of values) {
      try {
        const b = await send<{ id: number; mode: string; state: string }>("POST", "/api/v1/blocks", { value: v, note: "from a bulk check" });
        made += 1;
        setRows((xs) => xs.map((r) => (r.query.value === v ? { ...r, block: b } : r)));
      } catch (e) {
        why.push((e as Error).message);
      }
    }
    setBlockMsg(`${made} blocked in monitor mode${why.length ? `, ${why.length} refused (${why[0]})` : ""}.`);
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Bulk check" sub="Paste anything (an alert, a log, an email, a list) or upload text files. Every IP, domain, URL, hash and email in it is checked." />
        <form onSubmit={run} className="space-y-4">
          <textarea value={text} onChange={(e) => setText(e.target.value)} rows={7} className="ctl h-auto w-full py-3 font-mono text-[13px]" placeholder={"185.220.101[.]34\nhxxp://bad.example/payload\n44d88612fea8a8f36de82e1278abb02f"} spellCheck={false} />
          <div className="flex flex-wrap items-center gap-x-5 gap-y-3">
            <label className="btn-ghost h-9 cursor-pointer">
              <FileUp className="h-4 w-4" /> {files.length ? `${files.length} file${files.length === 1 ? "" : "s"}` : "Upload files"}
              <input type="file" multiple className="sr-only" accept=".txt,.csv,.log,.json,.eml,.md,text/*" onChange={(e) => setFiles([...(e.target.files ?? [])])} />
            </label>
            <TlpSelect value={tlp} onChange={setTlp} />
            <label className="flex items-center gap-2 text-[13px] text-ink-muted" title="Off: only our intel and saved answers; nothing is sent out and no quota is spent">
              <input type="checkbox" className="h-4 w-4 accent-accent" checked={providers} onChange={(e) => setProviders(e.target.checked)} /> Ask providers
            </label>
            <label className="flex items-center gap-2 text-[13px] text-ink-muted" title="Malicious results go on the blocklist in monitor mode as they arrive">
              <input type="checkbox" className="h-4 w-4 accent-down" checked={autoblock} disabled={!analyst} onChange={(e) => setAutoblock(e.target.checked)} /> Block malicious automatically
            </label>
            <div className="ml-auto flex gap-2">
              {running && (
                <button type="button" className="btn-ghost h-10" onClick={() => abort.current?.abort()}>
                  <Square className="h-4 w-4" /> Stop
                </button>
              )}
              <button className="btn-primary h-10 px-5" disabled={running || (!text.trim() && !files.length) || !analyst}>
                {running ? <Loader2 className="h-4 w-4 animate-spin" /> : null} Check all
              </button>
            </div>
          </div>
          {!analyst && <p className="text-[12.5px] text-ink-muted">Bulk checks need the analyst role.</p>}
        </form>
      </Card>

      {error && <p role="alert" className="rounded-card border border-down/30 bg-down/[0.06] px-4 py-3 text-[13.5px] text-down">{error}</p>}

      {progress && (
        <Card className="!p-0">
          <div className="p-5 sm:p-6">
            <div className="mb-2 flex items-center justify-between text-[13px]">
              <span className="text-ink-muted">{summary ? `Done: ${summary.total} checked${summary.providers ? `, ${summary.calls} provider calls` : ", our intel only"}` : `Checking ${progress[1]} values…`}</span>
              <span className="font-semibold tabular-nums">{progress[0]} / {progress[1]}</span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-line">
              <div className={`h-full rounded-full transition-[width] ${summary ? "bg-up" : "bg-gradient-to-r from-accent to-accent-soft"}`} style={{ width: `${(100 * progress[0]) / Math.max(1, progress[1])}%` }} />
            </div>
            {notes.length > 0 && <p className="mt-2 text-[12.5px] text-warn">{notes.join(" · ")}</p>}
            {summary && (summary.blocked.length > 0 || summary.refused.length > 0) && (
              <p className="mt-2 text-[12.5px] text-ink-muted">
                {summary.blocked.length} blocked automatically{summary.refused.length ? `; ${summary.refused.length} refused: ${summary.refused[0]}` : ""}
              </p>
            )}
            <div className="mt-5 flex flex-wrap items-center gap-3">
              <Segmented
                value={filter}
                options={FILTERS}
                onChange={setFilter}
                label="Show"
              />
              {summary && rows.length > 0 && (
                <button className="btn-ghost ml-auto h-8 text-[13px]" onClick={() => downloadCsv(shown)} title="Values stay defanged in the file">
                  <Download className="h-3.5 w-3.5" /> Export CSV
                </button>
              )}
              <span className="text-[12.5px] text-ink-faint">
                {(["malicious", "suspicious", "unknown", "benign"] as const).map((v) => `${counts[v] ?? 0} ${v === "unknown" ? "unknown" : v}`).join(" · ")}
              </span>
            </div>
          </div>
          {analyst && pickedRows.length > 0 && (
            <div className="flex flex-wrap items-center gap-3 border-t border-line bg-card-2/40 px-5 py-3 sm:px-6">
              <span className="text-[13px] font-medium">{pickedRows.length} picked</span>
              <button className="btn-ghost h-9" onClick={blockPicked}>
                <ShieldBan className="h-4 w-4" /> Block picked
              </button>
              <FlagButtons values={pickedRows.map((r) => r.query.value)} tlp={tlp} />
              {blockMsg && <span className="text-[12.5px] text-ink-muted">{blockMsg}</span>}
            </div>
          )}
          <div className="overflow-x-auto">
            <table className="w-full min-w-[980px] text-left text-[13.5px]">
              <thead>
                <tr className="border-y border-line bg-card-2/50 text-[12px] uppercase tracking-wide text-ink-muted">
                  <th className="w-10 py-3 pl-6" aria-label="Pick" />
                  <th className="py-3 font-medium">Value</th>
                  <th className="py-3 font-medium">Verdict</th>
                  <th className="py-3 text-right font-medium">Score</th>
                  <th className="py-3 pl-6 font-medium">Our intel</th>
                  <th className="py-3 font-medium">Country</th>
                  <th className="py-3 font-medium">Providers</th>
                  <th className="py-3 pr-6 font-medium">Here</th>
                </tr>
              </thead>
              <tbody>
                {shown.map((r) => (
                  <tr key={r.query.value} className="border-b border-line/70 odd:bg-zebra hover:bg-row-hover">
                    <td className="py-3 pl-6">
                      {analyst && <input type="checkbox" className="h-4 w-4 accent-accent" checked={picked.has(r.query.value)} onChange={() => toggle(r.query.value)} aria-label={`Pick ${r.query.value}`} />}
                    </td>
                    <td className="max-w-[360px] py-3 pr-4">
                      <a href={`/app/verify?q=${encodeURIComponent(r.query.value)}`} className="hover:text-accent-soft">
                        <Ioc value={r.query.value} className="text-[13px]" />
                      </a>
                      <span className="block text-[12px] text-ink-faint">{r.query.typeLabel}</span>
                    </td>
                    <td className="py-3">
                      <VerdictPill verdict={r.verdict} label={r.verdictLabel} />
                      <span className="mt-0.5 block text-[12px] text-ink-faint">{r.actionLabel}</span>
                    </td>
                    <td className="py-3 text-right">
                      <Score n={r.score} />
                    </td>
                    <td className="py-3 pl-6 text-ink-muted">{r.sources.join(", ") || (r.known ? "analyst" : "–")}</td>
                    <td className="py-3 text-ink-muted">{r.country ?? "–"}</td>
                    <td className="py-3">
                      <span className="flex flex-wrap gap-1">
                        {r.signals.map((s) => (
                          <span key={s.name} className={`rounded px-1.5 text-[11.5px] font-semibold ${SIG[s.kind] ?? SIG.info}`} title={s.text}>
                            {s.name}
                            {s.figure != null && ` ${s.figure}`}
                          </span>
                        ))}
                        {!r.signals.length && <span className="text-ink-faint">–</span>}
                      </span>
                    </td>
                    <td className="py-3 pr-6">
                      <span className="flex flex-wrap gap-1">
                        {r.asset && <span className="rounded bg-tint px-1.5 text-[11.5px] text-accent-soft">our asset</span>}
                        {r.block && <span className={`rounded px-1.5 text-[11.5px] ${r.block.mode === "enforce" ? "bg-down/15 text-down" : "bg-info/10 text-info-soft"}`}>blocked</span>}
                        {r.analystVerdict && <span className="rounded bg-chip px-1.5 text-[11.5px] text-chip-ink">{r.analystVerdict === "tp" ? "flagged" : "not malicious"}</span>}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!shown.length && <Empty>{rows.length ? "No result of this kind." : "Results appear here as each value is answered."}</Empty>}
          </div>
        </Card>
      )}
    </div>
  );
}
