import { AlertTriangle, Radar, Server, Timer, type LucideIcon } from "lucide-react";
import type { Kpi } from "../data/sample";
import { Change } from "./ui";

const ICONS: Record<Kpi["icon"], LucideIcon> = { radar: Radar, server: Server, alert: AlertTriangle, timer: Timer };
// Fewer exposures and a shorter time to verify are good news.
const LOWER_IS_BETTER = new Set<Kpi["icon"]>(["alert", "timer"]);

export default function KpiCard({ kpi, first }: { kpi: Kpi; first?: boolean }) {
  const Icon = ICONS[kpi.icon];
  return (
    <div className={`flex flex-col gap-3 py-4 sm:px-5 ${first ? "sm:pl-0" : ""}`}>
      <div className="flex items-center gap-2">
        <span className="inline-flex h-7 w-7 items-center justify-center rounded-lg bg-accent/10 text-accent-soft ring-1 ring-accent/20">
          <Icon className="h-[15px] w-[15px]" />
        </span>
        <span className="label">{kpi.label}</span>
      </div>
      <div className="flex items-end gap-2.5">
        <span className="text-[28px] font-bold leading-none tracking-tight text-ink tabular-nums">{kpi.value}</span>
        <Change value={kpi.change} invert={LOWER_IS_BETTER.has(kpi.icon)} />
      </div>
      <span className="text-[12px] text-ink-faint">{kpi.hint}</span>
    </div>
  );
}
