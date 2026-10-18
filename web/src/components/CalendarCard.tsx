import { ChevronLeft, ChevronRight } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { Failed, Skeleton } from "./states";
import { Card, CardHead } from "./ui";

interface Day {
  date: string;
  day: number;
  new: number;
  malicious: number;
  cases: number;
  blocks: number;
}

interface Month {
  month: string;
  label: string;
  prev: string;
  next: string | null;
  firstWeekday: number;
  today: string | null;
  max: number;
  days: Day[];
}

const WEEK = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

function nextDay(iso: string): string {
  const d = new Date(`${iso}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10);
}

/** A month of activity: shading = new indicators that day, red = malicious;
 * a day opens the indicators added on it. */
export default function CalendarCard() {
  const [month, setMonth] = useState<string>();
  const { data, error, reload } = useApi<Month>("calendar", { month });
  return (
    <Card>
      <CardHead title="Activity calendar" sub={data ? `${data.label} · click a day for what arrived` : "New indicators, cases and blocks per day"}>
        <span className="inline-flex items-center gap-1">
          <button className="btn-ghost h-8 w-8 !px-0" onClick={() => data && setMonth(data.prev)} aria-label="Previous month" disabled={!data}>
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button className="btn-ghost h-8 w-8 !px-0" onClick={() => data?.next && setMonth(data.next)} aria-label="Next month" disabled={!data?.next}>
            <ChevronRight className="h-4 w-4" />
          </button>
        </span>
      </CardHead>
      {error && !data ? (
        <Failed error={error} onRetry={reload} />
      ) : !data ? (
        <Skeleton className="h-64" />
      ) : (
        <>
          <div className="grid grid-cols-7 gap-1 text-center text-[11px] uppercase tracking-wide text-ink-faint">
            {WEEK.map((w) => (
              <span key={w}>{w}</span>
            ))}
          </div>
          <div className="mt-1 grid grid-cols-7 gap-1">
            {Array.from({ length: data.firstWeekday }, (_, i) => (
              <span key={`pad-${i}`} />
            ))}
            {data.days.map((d) => {
              const heat = data.max ? Math.sqrt(d.new / data.max) : 0;
              const title = `${d.date}: ${d.new.toLocaleString()} new (${d.malicious.toLocaleString()} malicious) · ${d.cases} case${d.cases === 1 ? "" : "s"} · ${d.blocks} block${d.blocks === 1 ? "" : "s"}`;
              const body = (
                <>
                  <span className={`text-[12px] ${d.date === data.today ? "font-bold text-accent-soft" : "text-ink-muted"}`}>{d.day}</span>
                  {d.new > 0 && <span className="text-[11px] font-semibold tabular-nums text-ink">{d.new > 999 ? `${Math.round(d.new / 100) / 10}k` : d.new}</span>}
                  <span className="flex h-1.5 items-center gap-0.5">
                    {d.malicious > 0 && <span className="h-1.5 w-1.5 rounded-full bg-down" />}
                    {d.cases > 0 && <span className="h-1.5 w-1.5 rounded-full bg-accent" />}
                    {d.blocks > 0 && <span className="h-1.5 w-1.5 rounded-full bg-warn" />}
                  </span>
                </>
              );
              const cls = "flex aspect-square flex-col items-center justify-center gap-0.5 rounded-ctl ring-1 ring-line/60";
              const style = { background: `rgb(var(--teal) / ${(heat * 0.45).toFixed(3)})` };
              return d.new > 0 ? (
                <Link key={d.date} to={`/indicators?added_from=${d.date}&added_until=${nextDay(d.date)}&sort=priority`} title={title} className={`${cls} hover:ring-accent/60`} style={style}>
                  {body}
                </Link>
              ) : (
                <span key={d.date} title={title} className={cls}>
                  {body}
                </span>
              );
            })}
          </div>
          <p className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-ink-faint">
            <span>Shading: new indicators</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-down" /> malicious</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-accent" /> case opened</span>
            <span className="inline-flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-warn" /> block placed</span>
          </p>
        </>
      )}
    </Card>
  );
}
