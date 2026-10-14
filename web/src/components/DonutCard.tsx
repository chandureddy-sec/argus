import { useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { platforms } from "../data/sample";
import { Card, CardHead, Select, reducedMotion, token } from "./ui";

/** Concentric rings, one per platform, each filled to its share of the largest. */
export default function DonutCard() {
  const [env, setEnv] = useState("All environments");
  const rings = platforms[env];
  const total = rings.reduce((a, r) => a + r.value, 0);
  const max = Math.max(...rings.map((r) => r.value));
  return (
    <Card delay={160} className="flex flex-col">
      <CardHead title="Assets by platform" sub="What ReconX found and fingerprinted">
        <Select value={env} options={Object.keys(platforms)} onChange={setEnv} label="Environment" />
      </CardHead>
      <div className="relative mx-auto h-[230px] w-full max-w-[260px]">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            {rings.map((r, i) => {
              const outer = 108 - i * 22;
              return (
                <Pie
                  key={`${env}-${r.name}`}
                  data={[
                    { name: r.name, value: r.value },
                    { name: "rest", value: max * 1.18 - r.value },
                  ]}
                  dataKey="value"
                  startAngle={90}
                  endAngle={-270}
                  innerRadius={outer - 13}
                  outerRadius={outer}
                  cornerRadius={10}
                  stroke="none"
                  animationBegin={i * 120}
                  animationDuration={900}
                  isAnimationActive={!reducedMotion}
                >
                  <Cell fill={token(r.color)} />
                  <Cell fill={token("line", 0.7)} />
                </Pie>
              );
            })}
            <Tooltip
              cursor={false}
              content={({ active, payload }) =>
                active && payload?.length && payload[0].name !== "rest" ? (
                  <div className="rounded-ctl border border-line bg-card-2/95 px-3 py-1.5 text-[13px] shadow-xl">
                    <b className="tabular-nums">{Number(payload[0].value).toLocaleString()}</b>{" "}
                    <span className="text-ink-muted">{String(payload[0].name)}</span>
                  </div>
                ) : null
              }
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-[26px] font-bold tabular-nums">{total.toLocaleString()}</span>
          <span className="label">Total assets</span>
        </div>
      </div>
      <dl className="mt-6 grid grid-cols-3 gap-3 border-t border-line pt-5">
        {rings.map((r) => (
          <div key={r.name}>
            <dt className="flex items-center gap-1.5 text-[12px] text-ink-muted">
              <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: token(r.color) }} />
              <span className="truncate">{r.name}</span>
            </dt>
            <dd className="mt-1 text-[17px] font-semibold tabular-nums">{r.value.toLocaleString()}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}
