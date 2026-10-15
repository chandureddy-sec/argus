import { AlertTriangle, Database, Radar, Server, type LucideIcon } from "lucide-react";
import type { Kpi } from "../lib/api";
import { Change, compact } from "./ui";

const ICONS: Record<Kpi["icon"], LucideIcon> = { radar: Radar, server: Server, alert: AlertTriangle, feed: Database };
/** One data-viz hue per metric, as in the reference dashboard. */
const TONE: Record<Kpi["icon"], string> = {
  radar: "bg-teal/12 text-teal ring-teal/25",
  alert: "bg-terracotta/12 text-terracotta ring-terracotta/25",
  server: "bg-sage/15 text-sage ring-sage/30",
  feed: "bg-plum/12 text-plum ring-plum/25",
};

export default function KpiCard({ kpi, first }: { kpi: Kpi; first?: boolean }) {
  const Icon = ICONS[kpi.icon];
  return (
    <div className={`flex flex-col gap-3 py-4 sm:px-5 ${first ? "sm:pl-0" : ""}`}>
      <div className="flex items-center gap-2">
        <span className={`inline-flex h-7 w-7 items-center justify-center rounded-lg ring-1 ${TONE[kpi.icon]}`}>
          <Icon className="h-[15px] w-[15px]" />
        </span>
        <span className="label">{kpi.label}</span>
      </div>
      <div className="flex items-end gap-2.5">
        <span className="text-[28px] font-bold leading-none tracking-tight text-ink tabular-nums" title={kpi.value.toLocaleString()}>
          {compact(kpi.value)}
          {kpi.of !== undefined && <span className="text-[18px] font-semibold text-ink-faint"> / {kpi.of}</span>}
        </span>
        {kpi.change !== null && <Change value={kpi.change} />}
      </div>
      <span className="text-[12px] text-ink-faint">{kpi.hint}</span>
    </div>
  );
}
