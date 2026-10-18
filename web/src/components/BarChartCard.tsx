import { useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useNavigate } from "react-router-dom";
import { useApi, type Collection } from "../lib/api";
import { Failed, Skeleton } from "./states";
import { Card, CardHead, Legend, Select, reducedMotion, useToken } from "./ui";

type Day = Collection["days"][number];

function Tip({ active, payload }: { active?: boolean; payload?: { payload: Day }[] }) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="rounded-ctl border border-line bg-card-2/95 px-3 py-2 text-[13px] shadow-xl">
      <p className="mb-1 font-semibold">{d.day}</p>
      <p className="text-ink-muted">
        <b className="text-ink tabular-nums">{d.ok}</b> pulled · <b className="text-ink tabular-nums">{d.other}</b> skipped or failed
      </p>
      <p className="mt-1 text-[11.5px] text-ink-faint">Click to list what was added that day</p>
    </div>
  );
}

/** Feed pulls per weekday. Becomes scan activity once the ReconX engine runs in the stack. */
export default function BarChartCard() {
  const nav = useNavigate();
  const [week, setWeek] = useState("This week");
  const token = useToken();
  const { data, error, reload } = useApi<Collection>("collection", { week });
  return (
    <Card delay={220} className="flex flex-col">
      <CardHead
        title="Collection activity"
        sub={data ? `${data.total} feed pulls · new data is matched locally, never at lookup time` : "Feed pulls per day"}
      >
        <Select value={week} options={data?.weeks ?? ["This week", "Last week"]} onChange={setWeek} label="Week" />
      </CardHead>
      <Legend
        items={[
          { name: "Pulled", color: "teal" },
          { name: "Skipped or failed", color: "terracotta" },
        ]}
      />
      <div className="mt-auto h-[270px] w-full pt-4">
        {error && !data ? (
          <Failed error={error} onRetry={reload} />
        ) : !data ? (
          <Skeleton className="h-full w-full" />
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              key={week}
              data={data.days}
              barGap={4}
              barCategoryGap="28%"
              margin={{ top: 6, right: 4, left: -18, bottom: 0 }}
              className="cursor-pointer"
              onClick={(st: { activeTooltipIndex?: number | string | null }) => {
                const d = data.days[Number(st?.activeTooltipIndex ?? -1)];
                if (!d) return;
                const next = new Date(`${d.date}T00:00:00Z`);
                next.setUTCDate(next.getUTCDate() + 1);
                nav(`/indicators?added_from=${d.date}&added_until=${next.toISOString().slice(0, 10)}&sort=priority`);
              }}
            >
              <CartesianGrid vertical={false} />
              <XAxis dataKey="day" axisLine={false} tickLine={false} tickMargin={10} />
              <YAxis axisLine={false} tickLine={false} width={44} allowDecimals={false} />
              <Tooltip content={<Tip />} cursor={{ fill: token("ink", 0.05), radius: 8 }} />
              <Bar dataKey="ok" fill={token("teal")} radius={[6, 6, 2, 2]} maxBarSize={18} animationDuration={800} isAnimationActive={!reducedMotion} />
              <Bar dataKey="other" fill={token("terracotta")} radius={[6, 6, 2, 2]} maxBarSize={18} animationDuration={1000} isAnimationActive={!reducedMotion} />
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  );
}
