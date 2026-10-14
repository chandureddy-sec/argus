import { useState } from "react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { useApi, type Types } from "../lib/api";
import { Empty, Failed, Skeleton } from "./states";
import { Card, CardHead, Select, compact, reducedMotion, token } from "./ui";

const RING_COLORS = ["accent", "accent-soft", "accent-muted"];

/** Concentric rings for the three largest indicator types, each filled to its share of
 * the total. A small share still gets a visible arc (MIN_ARC); the tooltip shows the real count. */
const MIN_ARC = 4; // percent of the circle
export default function DonutCard() {
  const [scope, setScope] = useState("Active");
  const { data, error, reload } = useApi<Types>("types", { scope });
  const rings = (data?.items ?? []).slice(0, 3).map((r, i) => ({ ...r, color: RING_COLORS[i] }));
  const others = (data?.items ?? []).slice(3);
  const total = Math.max(1, data?.total ?? 0);
  return (
    <Card delay={160} className="flex flex-col">
      <CardHead title="Indicators by type" sub="What your feeds report, within your clearance">
        <Select value={scope} options={data?.scopes ?? ["Active", "Malicious", "All"]} onChange={setScope} label="Which indicators" />
      </CardHead>
      {error && !data ? (
        <Failed error={error} onRetry={reload} />
      ) : !data ? (
        <Skeleton className="mx-auto h-[230px] w-[230px] !rounded-full" />
      ) : !data.total ? (
        <Empty>No indicators yet: switch on a feed in the Feed catalog.</Empty>
      ) : (
        <>
          <div className="relative mx-auto h-[230px] w-full max-w-[260px]">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                {rings.map((r, i) => {
                  const outer = 108 - i * 22;
                  return (
                    <Pie
                      key={`${scope}-${r.type}`}
                      data={[
                        { name: r.name, value: Math.max(MIN_ARC, (100 * r.value) / total), count: r.value },
                        { name: "rest", value: 100 - Math.max(MIN_ARC, (100 * r.value) / total), count: 0 },
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
                        <b className="tabular-nums">{Number(payload[0].payload.count).toLocaleString()}</b>{" "}
                        <span className="text-ink-muted">{String(payload[0].name)}</span>
                      </div>
                    ) : null
                  }
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
              <span className="text-[26px] font-bold tabular-nums" title={data.total.toLocaleString()}>
                {data.total.toLocaleString()}
              </span>
              <span className="label">{scope === "All" ? "Indicators" : `${scope} indicators`}</span>
            </div>
          </div>
          <dl className="mt-6 grid grid-cols-3 gap-3 border-t border-line pt-5">
            {rings.map((r) => (
              <div key={r.type}>
                <dt className="flex items-center gap-1.5 text-[12px] text-ink-muted">
                  <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: token(r.color) }} />
                  <span className="truncate">{r.name}</span>
                </dt>
                <dd className="mt-1 text-[17px] font-semibold tabular-nums">{r.value.toLocaleString()}</dd>
              </div>
            ))}
          </dl>
          {others.length > 0 && (
            <p className="mt-3 text-[12px] text-ink-faint">
              Also: {others.map((o) => `${o.name} ${compact(o.value)}`).join(" · ")}
            </p>
          )}
        </>
      )}
    </Card>
  );
}
