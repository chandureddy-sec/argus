import { AlertTriangle } from "lucide-react";
import { useApi, type EngineStatus } from "../lib/api";

export function ModePill({ mode }: { mode: string }) {
  const tone =
    mode === "passive"
      ? "bg-info/10 text-info-soft ring-info/20"
      : mode === "active"
        ? "bg-warn/10 text-warn ring-warn/25"
        : "bg-down/10 text-down ring-down/20";
  return <span className={`inline-flex rounded-full px-2.5 py-0.5 text-[12px] font-medium capitalize ring-1 ${tone}`}>{mode === "both" ? "passive + active" : mode}</span>;
}

const SEV: Record<string, string> = {
  critical: "bg-down/15 text-down ring-down/30",
  high: "bg-down/10 text-down ring-down/20",
  medium: "bg-warn/10 text-warn ring-warn/25",
  low: "bg-info/10 text-info-soft ring-info/20",
  info: "bg-chip text-chip-ink ring-line",
};

export function SevPill({ sev }: { sev: string }) {
  const s = sev.toLowerCase();
  return <span className={`inline-flex rounded-full px-2.5 py-0.5 text-[12px] font-semibold capitalize ring-1 ${SEV[s] ?? SEV.info}`}>{s}</span>;
}

/** Counts per severity, compact: "2 high · 1 med". */
export function FindingCounts({ high, medium, low }: { high: number; medium: number; low: number }) {
  if (!high && !medium && !low) return <span className="text-ink-faint">none</span>;
  return (
    <span className="flex flex-wrap gap-1.5">
      {high > 0 && <span className="rounded bg-down/10 px-1.5 text-[12px] font-semibold text-down">{high} high</span>}
      {medium > 0 && <span className="rounded bg-warn/10 px-1.5 text-[12px] font-semibold text-warn">{medium} med</span>}
      {low > 0 && <span className="rounded bg-accent/10 px-1.5 text-[12px] font-semibold text-accent-soft">{low} low</span>}
    </span>
  );
}

/** Says so, plainly, when the recon engine isn't running. */
export function EngineBanner() {
  const { data } = useApi<EngineStatus>("recon/status");
  if (!data || data.reachable) return null;
  return (
    <div role="alert" className="flex items-start gap-3 rounded-card border border-warn/30 bg-warn/[0.07] px-4 py-3 text-[13.5px]">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-warn" />
      <p className="text-ink-muted">
        <b className="text-ink">The recon engine isn't {data.configured ? "answering" : "set up"}.</b>{" "}
        {data.configured ? "It may still be starting. Run .\\tl up to start the stack, then reload." : "Set TL_RECONX_URL (the Docker stack does this for you)."}
      </p>
    </div>
  );
}
