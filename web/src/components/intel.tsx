import { Check, Copy } from "lucide-react";
import { useState } from "react";
import type { Card as ProviderCard } from "../lib/api";
import { ago } from "../lib/format";
import { copyRefanged, refang, TLPS } from "../lib/ioc";

/** An indicator value in its normal form (10.10.10.10, http://...). */
export function Ioc({ value, className = "", mono = true }: { value: string; className?: string; mono?: boolean }) {
  return <span className={`${mono ? "break-all font-mono" : "break-words"} ${className}`}>{refang(value)}</span>;
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState<boolean>();
  return (
    <button
      type="button"
      className="btn-ghost h-8 text-[12.5px]"
      title="Copies the value"
      onClick={async () => {
        setDone(await copyRefanged(value));
        setTimeout(() => setDone(undefined), 1500);
      }}
    >
      {done ? <Check className="h-3.5 w-3.5 text-up" /> : <Copy className="h-3.5 w-3.5" />}
      {done === undefined ? label : done ? "Copied" : "Copy failed"}
    </button>
  );
}

const VERDICT: Record<string, [string, string]> = {
  malicious: ["Malicious", "bg-down/12 text-down ring-down/25"],
  suspicious: ["Suspicious", "bg-warn/10 text-warn ring-warn/25"],
  unknown: ["No known threat", "bg-chip text-chip-ink ring-line"],
  benign: ["Clean", "bg-up/10 text-up ring-up/20"],
};

export function VerdictPill({ verdict, label }: { verdict: string; label?: string }) {
  const [text, tone] = VERDICT[verdict] ?? VERDICT.unknown;
  return <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[12px] font-semibold ring-1 ${tone}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{label ?? text}</span>;
}

const TLP_TONE: Record<string, string> = {
  "TLP:CLEAR": "text-ink ring-line",
  "TLP:GREEN": "text-up ring-up/30",
  "TLP:AMBER": "text-warn ring-warn/30",
  "TLP:AMBER+STRICT": "text-warn ring-warn/40",
  "TLP:RED": "text-down ring-down/40",
};

export function TlpTag({ tlp }: { tlp: string }) {
  return <span className={`inline-flex whitespace-nowrap rounded px-1.5 py-px font-mono text-[11px] font-semibold ring-1 ${TLP_TONE[tlp] ?? "text-ink-muted ring-line"}`} title="Who this may be shared with">{tlp}</span>;
}

export function TlpSelect({ value, onChange, label = "Marking" }: { value: string; onChange: (v: string) => void; label?: string }) {
  return (
    <label className="inline-flex items-center gap-2">
      <span className="label">{label}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} className="ctl h-8 text-[13px]">
        {TLPS.map((t) => (
          <option key={t}>{t}</option>
        ))}
      </select>
    </label>
  );
}

/** Score 0–100 as a number with a thin bar, coloured by verdict band. */
export function Score({ n, wide = false }: { n: number | null | undefined; wide?: boolean }) {
  if (n == null) return <span className="text-ink-faint">–</span>;
  const tone = n >= 60 ? "bg-down" : n >= 30 ? "bg-warn" : "bg-ink-faint";
  const text = n >= 60 ? "text-down" : n >= 30 ? "text-warn" : "text-ink-muted";
  return (
    <span className="inline-flex items-center justify-end gap-2.5">
      <span className={`h-1.5 overflow-hidden rounded-full bg-line ${wide ? "w-24" : "hidden w-16 md:block"}`}>
        <span className={`block h-full rounded-full ${tone}`} style={{ width: `${Math.round(n)}%` }} />
      </span>
      <span className={`w-7 text-right font-semibold tabular-nums ${text}`}>{Math.round(n)}</span>
    </span>
  );
}

export function StatusPill({ status }: { status: string }) {
  const map: Record<string, [string, string]> = {
    active: ["Active", "bg-up/10 text-up ring-up/20"],
    new: ["New", "bg-info/10 text-info-soft ring-info/20"],
    expired: ["Expired", "bg-down/10 text-down ring-down/20"],
    false_positive: ["Not malicious", "bg-chip text-chip-ink ring-line"],
    revoked: ["Revoked", "bg-chip text-chip-ink ring-line"],
  };
  const [text, tone] = map[status] ?? [status, "bg-chip text-chip-ink ring-line"];
  return <span className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-0.5 text-[12px] font-medium ring-1 ${tone}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{text}</span>;
}

export const TONE: Record<string, string> = {
  mal: "border-down/40 bg-down/[0.05]",
  sus: "border-warn/40 bg-warn/[0.04]",
  ok: "border-up/30 bg-up/[0.03]",
  info: "border-line bg-card",
  off: "border-line bg-card opacity-70",
};
const DOT: Record<string, string> = { mal: "bg-down", sus: "bg-warn", ok: "bg-up", info: "bg-info-soft", off: "bg-ink-faint" };

/** One provider's answer about an indicator (Verify page, indicator page). */
export function ProviderView({ c }: { c: ProviderCard }) {
  return (
    <article className={`animate-rise rounded-card border p-4 ${TONE[c.tone] ?? TONE.info}`}>
      <header className="mb-2 flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-[14px] font-semibold">
          <span className={`h-2 w-2 rounded-full ${DOT[c.tone] ?? DOT.info}`} />
          {c.title}
        </h3>
        <span className="text-[11.5px] text-ink-faint">
          {c.status === "cached" ? `saved ${ago(c.fetchedAt)}` : c.status === "stale" ? "last known answer" : c.status === "ok" ? "just now" : ""}
          {c.mode === "active" && " · contacts the target"}
        </span>
      </header>
      <p className="text-[13.5px] font-medium text-ink">
        <Ioc value={c.headline} mono={false} />
      </p>
      {c.rows.length > 0 && (
        <dl className="mt-3 grid grid-cols-[minmax(110px,auto)_1fr] gap-x-3 gap-y-1 text-[12.5px]">
          {c.rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-ink-faint">{k}</dt>
              <dd className="min-w-0 text-ink-muted">
                {Array.isArray(v) ? v.map((x) => <span key={x} className="block break-all"><Ioc value={x} mono={false} /></span>) : <Ioc value={String(v)} mono={false} />}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {c.evidence.length > 0 && (
        <ul className="mt-3 space-y-1 text-[12.5px]">
          {c.evidence.map((ev, i) => (
            <li key={i} className="flex gap-2">
              <span className={`shrink-0 rounded px-1.5 text-[11px] font-semibold ${ev.kind === "malicious" ? "bg-down/15 text-down" : ev.kind === "suspicious" ? "bg-warn/15 text-warn" : "bg-up/15 text-up"}`}>{ev.kind}</span>
              <span className="text-ink-muted"><Ioc value={ev.text} mono={false} /></span>
            </li>
          ))}
        </ul>
      )}
      {c.error && <p className="mt-2 text-[12px] text-warn">No answer this time ({c.error}), so this is the last one we saved.</p>}
    </article>
  );
}
