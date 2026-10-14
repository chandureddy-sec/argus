import { AlertTriangle, CheckCircle2, CircleDot, ExternalLink, Loader2, Save, XCircle } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Card, CardHead } from "../components/ui";
import { post, type Me, type ProgressEvent } from "../lib/api";
import { usePage } from "../lib/page";

interface Saved {
  file: string;
  import: { target: string; new_assets: number; updated_assets: number; hosts: number; ips: number; products: number; duplicate: boolean };
}

function Icon({ ev, last, running }: { ev: ProgressEvent; last: boolean; running: boolean }) {
  if (ev.level === "error") return <XCircle className="h-4 w-4 text-down" />;
  if (ev.level === "warn") return <AlertTriangle className="h-4 w-4 text-warn" />;
  if (ev.level === "done") return <CheckCircle2 className="h-4 w-4 text-up" />;
  if (last && running) return <Loader2 className="h-4 w-4 animate-spin text-accent" />;
  return <CircleDot className="h-4 w-4 text-accent-soft" />;
}

export default function Job({ me }: { me?: Me }) {
  const { id = "" } = useParams();
  usePage("Attack surface", "Scans", "Running scan");
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [state, setState] = useState<"running" | "done" | "error">("running");
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState<Saved>();
  const [error, setError] = useState<string>();
  const list = useRef<HTMLOListElement>(null);

  useEffect(() => {
    // The engine replays the whole history first, so a reload or reconnect catches up.
    setEvents([]);
    const es = new EventSource(`/app/api/recon/jobs/${encodeURIComponent(id)}/events`);
    es.onmessage = (m) => {
      const ev = JSON.parse(m.data) as ProgressEvent;
      setEvents((xs) => [...xs, ev]);
      if (ev.level === "done" || ev.step === "done") setState("done");
      if (ev.level === "error" && ev.step === "error") setState("error");
    };
    es.onerror = () => es.close(); // the stream ends when the scan does
    return () => es.close();
  }, [id]);

  useEffect(() => {
    list.current?.lastElementChild?.scrollIntoView({ block: "nearest" });
  }, [events.length]);

  const pct = Math.max(0, ...events.map((e) => e.percent));
  const last = events[events.length - 1];
  const target = events.find((e) => /scan(ning)?\s/i.test(e.message))?.message;

  const save = async () => {
    setSaving(true);
    setError(undefined);
    try {
      setSaved(await post<Saved>(`recon/jobs/${id}/save`));
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[980px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead
          title={state === "running" ? "Scan running" : state === "done" ? "Scan complete" : "Scan failed"}
          sub={target ?? `Job ${id}`}
        >
          {state === "done" && (
            <Link to={`/scans/view/${encodeURIComponent(`job:${id}`)}`} className="btn-primary">
              <ExternalLink className="h-4 w-4" /> Open results
            </Link>
          )}
        </CardHead>
        <div className="mb-2 flex items-center justify-between text-[13px]">
          <span className="text-ink-muted">{last?.message ?? "Connecting to the engine…"}</span>
          <span className="font-semibold tabular-nums">{pct}%</span>
        </div>
        <div className="h-2.5 overflow-hidden rounded-full bg-line" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
          <div
            className={`h-full rounded-full transition-[width] duration-500 ${state === "error" ? "bg-down" : state === "done" ? "bg-up" : "bg-gradient-to-r from-accent to-accent-soft"}`}
            style={{ width: `${pct}%` }}
          />
        </div>

        <ol ref={list} className="mt-6 max-h-[420px] space-y-1 overflow-y-auto pr-1" aria-live="polite">
          {events.map((ev, i) => (
            <li key={i} className="flex items-start gap-3 rounded-ctl px-2 py-1.5 hover:bg-card-2/60">
              <span className="mt-0.5">
                <Icon ev={ev} last={i === events.length - 1} running={state === "running"} />
              </span>
              <span className="min-w-0 flex-1 text-[13.5px]">
                <span className={ev.level === "warn" ? "text-warn" : ev.level === "error" ? "text-down" : "text-ink"}>{ev.message}</span>
                <span className="ml-2 text-[11.5px] uppercase tracking-wide text-ink-faint">{ev.step}</span>
              </span>
              <span className="text-[12px] tabular-nums text-ink-faint">{ev.percent}%</span>
            </li>
          ))}
        </ol>
      </Card>

      {state === "done" && (
        <Card>
          <CardHead title="Keep this scan" sub="Unsaved scans live only in the engine's memory. Saving writes the report and adds its hosts and IPs to your assets, where threat intel watches them." />
          {saved ? (
            <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-[14px]">
              <span className="inline-flex items-center gap-2 text-up">
                <CheckCircle2 className="h-5 w-5" /> Saved as <span className="font-mono text-[13px] text-ink">{saved.file}</span>
              </span>
              <span className="text-ink-muted">
                {saved.import.duplicate ? (
                  "Already in your assets."
                ) : (
                  <>
                    <b className="text-ink">{saved.import.new_assets}</b> new and <b className="text-ink">{saved.import.updated_assets}</b> updated assets ({saved.import.hosts} hosts, {saved.import.ips} IPs, {saved.import.products} products)
                  </>
                )}
              </span>
              <Link to={`/scans/view/${encodeURIComponent(saved.file)}`} className="btn-ghost ml-auto">
                Open saved scan
              </Link>
            </div>
          ) : (
            <div className="flex flex-wrap items-center gap-3">
              <button className="btn-primary" onClick={save} disabled={saving || me?.role === "viewer"}>
                {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save and add to assets
              </button>
              {me?.role === "viewer" && <span className="text-[13px] text-ink-muted">Saving needs the analyst role.</span>}
              {error && <span className="text-[13px] text-down">{error}</span>}
            </div>
          )}
        </Card>
      )}
    </div>
  );
}
