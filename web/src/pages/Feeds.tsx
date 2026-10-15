import { Loader2, Plus, RefreshCw } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { send, useV1, type Me, type SourceOut } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

const SHOW = ["All", "On", "Off", "Need attention", "Yours"] as const;
const KNOWLEDGE = new Set(["mitre_attack", "attack", "nvd", "epss", "osv", "cisa_kev"]);

export function every(minutes: number): string {
  if (!minutes) return "on demand";
  if (minutes % 1440 === 0) return `${minutes / 1440} d`;
  if (minutes % 60 === 0) return `${minutes / 60} h`;
  return `${minutes} min`;
}

export function Health({ s }: { s: SourceOut }) {
  const tone = !s.enabled ? "bg-ink-faint" : s.health === "ok" ? "bg-up" : s.health === "failing" ? "bg-down" : s.health === "degraded" ? "bg-warn" : "bg-ink-faint";
  return <span className={`inline-block h-2 w-2 shrink-0 rounded-full ${tone}`} title={s.enabled ? s.health : "switched off"} />;
}

export function Switch({ s, admin, onChange }: { s: SourceOut; admin: boolean; onChange: () => void }) {
  const [busy, setBusy] = useState(false);
  if (!admin) return <span className={`text-[12.5px] ${s.enabled ? "text-up" : "text-ink-faint"}`}>{s.enabled ? "On" : "Off"}</span>;
  return (
    <button
      role="switch"
      aria-checked={s.enabled}
      aria-label={`${s.title}: switch ${s.enabled ? "off" : "on"}`}
      disabled={busy}
      onClick={async () => {
        setBusy(true);
        try {
          await send("PATCH", `/api/v1/sources/${s.name}`, { enabled: !s.enabled });
          onChange();
        } finally {
          setBusy(false);
        }
      }}
      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${s.enabled ? "bg-accent" : "bg-ctl-line"} ${busy ? "opacity-60" : ""}`}
    >
      <span className={`inline-block h-[18px] w-[18px] rounded-full shadow transition-transform ${s.enabled ? "translate-x-[22px]" : "translate-x-[3px]"} bg-knob`} />
    </button>
  );
}

function Row({ s, admin, reload, onPull, pulling }: { s: SourceOut; admin: boolean; reload: () => void; onPull: (n: string) => void; pulling: boolean }) {
  return (
    <li className={`flex flex-wrap items-center gap-x-4 gap-y-2 px-5 py-3.5 sm:px-6 ${s.enabled ? "" : "opacity-60"}`}>
      <Health s={s} />
      <Link to={`/feeds/${s.name}`} className="min-w-0 flex-1 hover:text-accent-soft">
        <span className="block truncate font-medium">{s.title}</span>
        <span className="block truncate text-[12px] text-ink-faint">
          {s.kind.replace(/-/g, " ")}
          {s.requires_key && !s.key_configured && <span className="text-warn"> · needs an API key</span>}
          {s.enabled && s.health !== "ok" && s.last_error && <span className="text-warn"> · {s.last_error.slice(0, 70)}</span>}
        </span>
      </Link>
      <span className="w-10 text-center">
        <span className={`rounded px-1.5 py-0.5 text-[12px] font-semibold ${s.reliability === "A" ? "bg-up/10 text-up" : s.reliability === "B" ? "bg-warn/10 text-warn" : "bg-chip text-chip-ink"}`} title={s.reliability_note}>
          {s.reliability}
        </span>
      </span>
      <span className="w-28 text-[12.5px] text-ink-muted" title="last success">
        {s.kind === "enricher" ? "on demand" : ago(s.last_success_at)}
      </span>
      <span className="w-16 text-right text-[12.5px] tabular-nums text-ink-muted">{every(s.interval_minutes)}</span>
      <span className="flex w-36 items-center justify-end gap-3">
        {admin && s.enabled && s.kind !== "enricher" && (
          <button className="btn-ghost h-8 w-8 !px-0" title="Pull now" aria-label={`Pull ${s.title} now`} disabled={pulling} onClick={() => onPull(s.name)}>
            {pulling ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />}
          </button>
        )}
        <Switch s={s} admin={admin} onChange={reload} />
      </span>
    </li>
  );
}

export default function Feeds({ me }: { me?: Me }) {
  usePage("Platform", "Feed catalog");
  const { data, error, reload } = useV1<SourceOut[]>("sources");
  const [show, setShow] = useState<(typeof SHOW)[number]>("All");
  const [pulling, setPulling] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const admin = me?.role === "admin";

  const keep = (s: SourceOut) =>
    show === "All" || (show === "On" && s.enabled) || (show === "Off" && !s.enabled) || (show === "Need attention" && s.enabled && ["failing", "degraded"].includes(s.health)) || (show === "Yours" && s.custom);
  const all = data ?? [];
  const groups: [string, string, SourceOut[]][] = [
    ["Your feeds", "Added here; open one to edit or remove it", all.filter((s) => s.custom && keep(s))],
    ["Indicator feeds", "Built in; terms checked and recorded in docs/SOURCES.md", all.filter((s) => !s.custom && s.kind !== "enricher" && !KNOWLEDGE.has(s.name) && s.kind !== "knowledge" && s.kind !== "vulnerability" && keep(s))],
    ["Knowledge sources", "ATT&CK, vulnerabilities and exploit likelihood", all.filter((s) => !s.custom && (KNOWLEDGE.has(s.name) || s.kind === "knowledge" || s.kind === "vulnerability") && keep(s))],
    ["Lookup providers", "Asked live by Verify and Bulk check; switch one off to stop asking it", all.filter((s) => s.kind === "enricher" && keep(s))],
  ];
  const on = all.filter((s) => s.enabled && s.kind !== "enricher").length;
  const failing = all.filter((s) => s.enabled && ["failing", "degraded"].includes(s.health)).length;

  const pull = async (name: string) => {
    setPulling(name);
    setMsg(undefined);
    try {
      const r = await send<{ queued: boolean }>("POST", `/api/v1/sources/${name}/run`);
      setMsg(r.queued ? "Pull queued; the worker runs it next." : "Already queued.");
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setPulling(undefined);
    }
  };
  const syncAll = async () => {
    setPulling("*");
    setMsg(undefined);
    try {
      const r = await send<{ queued: string[] }>("POST", "/api/v1/sources/sync");
      setMsg(`${r.queued.length} sources queued; those that ran recently wait for their minimum gap.`);
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setPulling(undefined);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {[
          ["Pulling", on, "feeds switched on"],
          ["Need attention", failing, "failing or degraded"],
          ["Your feeds", all.filter((s) => s.custom).length, "added in this catalog"],
          ["Sources", all.length, "feeds, knowledge, lookups"],
        ].map(([l, v, h]) => (
          <div key={String(l)} className="card p-4">
            <p className="label">{l}</p>
            <p className="mt-1.5 text-[26px] font-bold tabular-nums">{data ? v : "–"}</p>
            <p className="text-[12px] text-ink-faint">{h}</p>
          </div>
        ))}
      </div>

      <Card>
        <CardHead title="Feed catalog" sub="Each feed pulls known-bad indicators on a schedule into our own store, so checks run locally with no outside call at detection time.">
          {admin && (
            <>
              <button className="btn-ghost h-9" onClick={syncAll} disabled={!!pulling}>
                {pulling === "*" ? <Loader2 className="h-4 w-4 animate-spin" /> : <RefreshCw className="h-4 w-4" />} Sync all feeds
              </button>
              <Link to="/feeds/new" className="btn-primary">
                <Plus className="h-4 w-4" /> Add source
              </Link>
            </>
          )}
        </CardHead>
        <div className="flex flex-wrap items-center gap-3">
          <Segmented value={show} options={SHOW} onChange={setShow} label="Show" />
          {msg && <span className="text-[13px] text-ink-muted">{msg}</span>}
        </div>
      </Card>

      {error && !data ? (
        <Card>
          <Failed error={error} onRetry={reload} />
        </Card>
      ) : !data ? (
        <Skeleton className="h-64" />
      ) : (
        groups.map(([title, sub, rows]) =>
          rows.length || (title === "Your feeds" && (show === "All" || show === "Yours")) ? (
            <Card key={title} className="!p-0">
              <div className="p-5 pb-3 sm:p-6 sm:pb-3">
                <CardHead title={title} sub={sub} />
              </div>
              {rows.length ? (
                <ul className="divide-y divide-line/70 border-t border-line">
                  {rows.map((s) => (
                    <Row key={s.name} s={s} admin={admin} reload={reload} onPull={pull} pulling={pulling === s.name} />
                  ))}
                </ul>
              ) : (
                <p className="border-t border-line px-6 py-6 text-[13.5px] text-ink-muted">
                  No feeds of your own yet. Any plain-text, CSV or JSON list of IPs, domains, URLs or hashes at an http(s) address works, optionally with an API key.{" "}
                  {admin && (
                    <Link to="/feeds/new" className="text-accent-soft hover:underline">
                      Add one
                    </Link>
                  )}
                </p>
              )}
            </Card>
          ) : null,
        )
      )}
    </div>
  );
}
