import { useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useNavigate } from "react-router-dom";
import { useApi, type Activity, type Point, type Range } from "../lib/api";
import { Failed, Skeleton } from "./states";
import { Card, Change, Legend, Segmented, compact, reducedMotion, useToken } from "./ui";

const RANGES = ["Year", "Month", "Week", "Day"] as const;
const SINCE: Record<Range, string> = { Year: "in 12 months", Month: "in 30 days", Week: "in 7 days", Day: "in 24 hours" };

function Tip({ active, payload }: { active?: boolean; payload?: { payload: Point }[] }) {
  if (!active || !payload?.length) return null;
  const p = payload[0].payload;
  return (
    <div className="rounded-ctl border border-line bg-card-2/95 px-3 py-2 shadow-xl backdrop-blur">
      <p className="text-[15px] font-bold text-ink tabular-nums">
        {compact(p.malicious)}
        <span className="font-normal text-ink-muted">, {p.date}</span>
      </p>
      <p className="mt-0.5 text-[12px] text-ink-muted">
        <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-teal align-middle" />
        {compact(p.suspicious)} suspicious
      </p>
    </div>
  );
}

export default function AreaChartCard() {
  const nav = useNavigate();
  const [range, setRange] = useState<Range>("Month");
  const token = useToken();
  const { data, error, loading, reload } = useApi<Activity>("activity", { range });
  return (
    <Card delay={80}>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="label">New indicators {SINCE[range]} <span className="normal-case tracking-normal text-ink-faint">· click a point to list them</span></p>
          <div className="mt-2 flex h-[34px] items-center gap-3">
            {data ? (
              <>
                <span className="text-[34px] font-bold leading-none tracking-tight tabular-nums" title={data.total.toLocaleString()}>
                  {compact(data.total)}
                </span>
                {data.change !== null && <Change value={data.change} />}
              </>
            ) : (
              <Skeleton className="h-8 w-32" />
            )}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <Legend
            items={[
              { name: "Malicious", color: "olive-gold" },
              { name: "Suspicious", color: "teal" },
            ]}
          />
          <Segmented value={range} options={RANGES} onChange={setRange} label="Time range" />
        </div>
      </div>
      <div className={`h-[280px] w-full transition-opacity sm:h-[300px] ${loading && data ? "opacity-60" : ""}`}>
        {error && !data ? (
          <Failed error={error} onRetry={reload} />
        ) : !data ? (
          <Skeleton className="h-full w-full" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart
              key={range}
              data={data.points}
              margin={{ top: 10, right: 6, left: -12, bottom: 0 }}
              className="cursor-pointer"
              onClick={(st: { activeTooltipIndex?: number | string | null }) => {
                const p = data.points[Number(st?.activeTooltipIndex ?? -1)];
                if (p) nav(`/indicators?added_from=${encodeURIComponent(p.from)}&added_until=${encodeURIComponent(p.to)}&min_score=30&sort=priority`);
              }}
            >
              <defs>
                <linearGradient id="fill-mal" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={token("olive-gold", 0.32)} />
                  <stop offset="100%" stopColor={token("olive-gold", 0)} />
                </linearGradient>
                <linearGradient id="fill-sus" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={token("teal", 0.16)} />
                  <stop offset="100%" stopColor={token("teal", 0)} />
                </linearGradient>
              </defs>
              <CartesianGrid vertical={false} strokeDasharray="0" />
              <XAxis dataKey="label" axisLine={false} tickLine={false} tickMargin={10} minTickGap={16} />
              <YAxis axisLine={false} tickLine={false} tickFormatter={compact} width={52} allowDecimals={false} />
              <Tooltip content={<Tip />} cursor={{ stroke: token("ink-faint", 0.6), strokeDasharray: "4 4" }} />
              <Area
                type="monotone"
                dataKey="suspicious"
                stroke={token("teal")}
                strokeWidth={2}
                fill="url(#fill-sus)"
                animationDuration={900}
                isAnimationActive={!reducedMotion}
                dot={false}
                activeDot={{ r: 4, fill: token("teal"), stroke: token("card"), strokeWidth: 2 }}
              />
              <Area
                type="monotone"
                dataKey="malicious"
                stroke={token("olive-gold")}
                strokeWidth={2.5}
                fill="url(#fill-mal)"
                animationDuration={1100}
                isAnimationActive={!reducedMotion}
                dot={false}
                activeDot={{ r: 5, fill: token("olive-gold"), stroke: token("card"), strokeWidth: 2 }}
              />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}
