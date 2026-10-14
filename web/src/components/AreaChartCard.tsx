import { useState } from "react";
import { Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { activity, activityTotal, type Point, type Range } from "../data/sample";
import { Card, Change, Legend, Segmented, compact, reducedMotion, token } from "./ui";

const RANGES = ["Year", "Month", "Week", "Day"] as const;

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
        <span className="mr-1.5 inline-block h-2 w-2 rounded-full bg-accent-soft align-middle" />
        {compact(p.suspicious)} suspicious
      </p>
    </div>
  );
}

export default function AreaChartCard() {
  const [range, setRange] = useState<Range>("Year");
  const data = activity[range];
  const total = activityTotal[range];
  return (
    <Card delay={80}>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
        <div>
          <p className="label">Detections</p>
          <div className="mt-2 flex items-center gap-3">
            <span className="text-[34px] font-bold leading-none tracking-tight tabular-nums">{total.value}</span>
            <Change value={total.change} />
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-4">
          <Legend
            items={[
              { name: "Malicious", color: "accent" },
              { name: "Suspicious", color: "accent-muted" },
            ]}
          />
          <Segmented value={range} options={RANGES} onChange={setRange} label="Time range" />
        </div>
      </div>
      <div className="glow-line h-[280px] w-full sm:h-[300px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart key={range} data={data} margin={{ top: 10, right: 6, left: -12, bottom: 0 }}>
            <defs>
              <linearGradient id="fill-mal" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={token("accent", 0.45)} />
                <stop offset="100%" stopColor={token("accent", 0)} />
              </linearGradient>
              <linearGradient id="fill-sus" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor={token("accent-muted", 0.18)} />
                <stop offset="100%" stopColor={token("accent-muted", 0)} />
              </linearGradient>
            </defs>
            <CartesianGrid vertical={false} strokeDasharray="0" />
            <XAxis dataKey="label" axisLine={false} tickLine={false} tickMargin={10} minTickGap={16} />
            <YAxis axisLine={false} tickLine={false} tickFormatter={compact} width={52} />
            <Tooltip
              content={<Tip />}
              cursor={{ stroke: token("accent", 0.5), strokeDasharray: "4 4" }}
            />
            <Area
              type="monotone"
              dataKey="suspicious"
              stroke={token("accent-muted")}
              strokeWidth={2}
              fill="url(#fill-sus)"
              animationDuration={900}
              isAnimationActive={!reducedMotion}
              dot={false}
              activeDot={{ r: 4, fill: token("accent-muted"), stroke: token("card"), strokeWidth: 2 }}
            />
            <Area
              type="monotone"
              dataKey="malicious"
              stroke={token("accent")}
              strokeWidth={2.5}
              fill="url(#fill-mal)"
              animationDuration={1100}
              isAnimationActive={!reducedMotion}
              dot={false}
              activeDot={{ r: 5, fill: token("accent"), stroke: "#fff", strokeWidth: 2 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
