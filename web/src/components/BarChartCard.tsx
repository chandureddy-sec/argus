import { useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { scans, type ScanDay } from "../data/sample";
import { Card, CardHead, Legend, Select, reducedMotion, token } from "./ui";

function Tip({ active, payload }: { active?: boolean; payload?: { payload: ScanDay }[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="rounded-ctl border border-line bg-card-2/95 px-3 py-2 text-[13px] shadow-xl">
      <p className="mb-1 font-semibold">{d.day}</p>
      <p className="text-ink-muted">
        <b className="text-ink tabular-nums">{d.passive}</b> passive · <b className="text-ink tabular-nums">{d.active}</b> active
      </p>
    </div>
  );
}

export default function BarChartCard() {
  const [week, setWeek] = useState("This week");
  const data = scans[week];
  const total = data.reduce((a, d) => a + d.passive + d.active, 0);
  return (
    <Card delay={220} className="flex flex-col">
      <CardHead title="Scan activity" sub={`${total} scans · passive OSINT and authorised active checks`}>
        <Select value={week} options={Object.keys(scans)} onChange={setWeek} label="Week" />
      </CardHead>
      <Legend
        items={[
          { name: "Passive", color: "accent" },
          { name: "Active", color: "accent-muted" },
        ]}
      />
      <div className="mt-auto h-[270px] w-full pt-4">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart key={week} data={data} barGap={4} barCategoryGap="28%" margin={{ top: 6, right: 4, left: -18, bottom: 0 }}>
            <CartesianGrid vertical={false} />
            <XAxis dataKey="day" axisLine={false} tickLine={false} tickMargin={10} />
            <YAxis axisLine={false} tickLine={false} width={44} />
            <Tooltip content={<Tip />} cursor={{ fill: token("accent", 0.06), radius: 8 }} />
            <Bar dataKey="passive" fill={token("accent")} radius={[6, 6, 2, 2]} maxBarSize={18} animationDuration={800} isAnimationActive={!reducedMotion} />
            <Bar dataKey="active" fill={token("accent-muted", 0.85)} radius={[6, 6, 2, 2]} maxBarSize={18} animationDuration={1000} isAnimationActive={!reducedMotion} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}
