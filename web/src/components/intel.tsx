import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { copyRefanged, TLPS } from "../lib/ioc";

/** Defang markers: [.] [:] [@] [://] and the hxxp/fxp schemes. */
const FANG = /(\[(?:\.|:|@|:\/\/)\]|hxxps?|fxp)/;

/** A defanged value that still reads normally: the brackets are drawn small and
 * faint (and hidden from screen readers) around a full-strength separator, so
 * 152[.]59[.]198[.]233 reads almost as 152.59.198.233. Copying it still copies
 * the defanged text; CopyButton gives the live value. */
export function Ioc({ value, className = "", mono = true }: { value: string; className?: string; mono?: boolean }) {
  const parts = value.split(FANG);
  return (
    <span className={`${mono ? "break-all font-mono" : "break-words"} ${className}`}>
      {parts.map((p, i) =>
        i % 2 === 0 ? (
          p
        ) : p.startsWith("[") ? (
          <span key={i}>
            <span className="fang" aria-hidden="true">[</span>
            {p.slice(1, -1)}
            <span className="fang" aria-hidden="true">]</span>
          </span>
        ) : (
          <span key={i} className="text-ink-faint">
            {p}
          </span>
        ),
      )}
    </span>
  );
}

export function CopyButton({ value, label = "Copy" }: { value: string; label?: string }) {
  const [done, setDone] = useState<boolean>();
  return (
    <button
      type="button"
      className="btn-ghost h-8 text-[12.5px]"
      title="Copies the live (refanged) value"
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
