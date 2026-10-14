import { ArrowRight, Minus, Plus, RefreshCw } from "lucide-react";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Select } from "../components/ui";
import { useApi, type ChangeSet, type ScanRow } from "../lib/api";
import { dateTime, scanRef } from "../lib/format";
import { usePage } from "../lib/page";

const SUMMARY: [string, string][] = [
  ["subdomains_added", "Subdomains added"],
  ["subdomains_removed", "Subdomains removed"],
  ["hosts_changed", "Hosts changed"],
  ["ips_added", "IPs added"],
  ["ips_removed", "IPs removed"],
  ["certificates_added", "Certificates issued"],
  ["dns_changes", "DNS changes"],
  ["provider_changes", "Provider changes"],
];
const ACTION = {
  added: ["bg-up/10 text-up ring-up/20", Plus],
  removed: ["bg-down/10 text-down ring-down/20", Minus],
  changed: ["bg-warn/10 text-warn ring-warn/25", RefreshCw],
} as const;

function label(r: ScanRow) {
  return `${dateTime(r.timestamp)} · ${r.mode}${r.file ? "" : " · unsaved"}`;
}

export default function Compare() {
  usePage("Attack surface", "Compare");
  const [params, setParams] = useSearchParams();
  const scans = useApi<ScanRow[]>("recon/scans");
  const a = params.get("a") ?? "";
  const b = params.get("b") ?? "";
  const byRef = useMemo(() => new Map((scans.data ?? []).map((r) => [scanRef(r), r])), [scans.data]);
  const target = byRef.get(b)?.target ?? byRef.get(a)?.target ?? "";
  const sameTarget = (scans.data ?? []).filter((r) => !target || r.target === target);
  const targets = [...new Set((scans.data ?? []).map((r) => r.target))];
  const ready = a && b && a !== b;
  const diff = useApi<ChangeSet>(ready ? "recon/compare" : "recon/status", ready ? { a, b } : {});
  const [cat, setCat] = useState("All changes");
  const set = (k: "a" | "b", v: string) => setParams((p) => (p.set(k, v), p), { replace: true });

  const events = (ready ? diff.data?.events ?? [] : []).filter((e) => cat === "All changes" || e.category === cat);
  const categories = ["All changes", ...new Set((diff.data?.events ?? []).map((e) => e.category))];

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Compare two scans" sub="What changed on a target's attack surface between two scans" />
        {scans.error && !scans.data ? (
          <Failed error={scans.error} onRetry={scans.reload} />
        ) : !scans.data ? (
          <Skeleton className="h-10 w-full" />
        ) : scans.data.length < 2 ? (
          <Empty>
            Compare needs two scans of the same target. <Link to="/scans/new" className="text-accent-soft hover:underline">Run another scan</Link>.
          </Empty>
        ) : (
          <div className="grid items-end gap-3 md:grid-cols-[1fr_1fr_auto_1fr]">
            <label>
              <span className="label mb-1.5 block">Target</span>
              <select
                className="ctl w-full"
                value={target}
                onChange={(e) => {
                  const rows = scans.data!.filter((r) => r.target === e.target.value);
                  setParams({ a: rows[1] ? scanRef(rows[1]) : "", b: rows[0] ? scanRef(rows[0]) : "" }, { replace: true });
                }}
              >
                <option value="">Choose…</option>
                {targets.map((t) => (
                  <option key={t}>{t}</option>
                ))}
              </select>
            </label>
            <label>
              <span className="label mb-1.5 block">Earlier scan</span>
              <select className="ctl w-full" value={a} onChange={(e) => set("a", e.target.value)}>
                <option value="">Choose…</option>
                {sameTarget.map((r) => (
                  <option key={scanRef(r)} value={scanRef(r)}>
                    {label(r)}
                  </option>
                ))}
              </select>
            </label>
            <ArrowRight className="mb-2.5 hidden h-5 w-5 text-ink-faint md:block" />
            <label>
              <span className="label mb-1.5 block">Later scan</span>
              <select className="ctl w-full" value={b} onChange={(e) => set("b", e.target.value)}>
                <option value="">Choose…</option>
                {sameTarget.map((r) => (
                  <option key={scanRef(r)} value={scanRef(r)}>
                    {label(r)}
                  </option>
                ))}
              </select>
            </label>
          </div>
        )}
      </Card>

      {ready && (
        <Card className="!p-0">
          {diff.error && !diff.data ? (
            <Failed error={diff.error} onRetry={diff.reload} />
          ) : !diff.data || !("summary" in diff.data) ? (
            <Skeleton className="m-6 h-40" />
          ) : (
            <>
              <div className="grid grid-cols-2 gap-px overflow-hidden rounded-t-card bg-line sm:grid-cols-4">
                {SUMMARY.map(([k, l]) => (
                  <div key={k} className="bg-card p-4 sm:p-5">
                    <p className="label">{l}</p>
                    <p className={`mt-1.5 text-[24px] font-bold tabular-nums ${diff.data!.summary[k] ? "text-ink" : "text-ink-faint"}`}>{diff.data!.summary[k] ?? 0}</p>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-3 p-5 sm:p-6">
                <h2 className="text-[15px] font-semibold">
                  {(diff.data.events ?? []).length} change{(diff.data.events ?? []).length === 1 ? "" : "s"}
                  <span className="ml-2 text-[13px] font-normal text-ink-muted">{diff.data.summary.unchanged_hosts ?? 0} hosts unchanged</span>
                </h2>
                <Select value={cat} options={categories} onChange={setCat} label="Kind of change" />
              </div>
              {events.length ? (
                <ul className="divide-y divide-line/70 border-t border-line">
                  {events.slice(0, 1000).map((e, i) => {
                    const [tone, Icon] = ACTION[e.action] ?? ACTION.changed;
                    return (
                      <li key={i} className="flex flex-wrap items-center gap-3 px-5 py-3 text-[13.5px] sm:px-6">
                        <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[12px] font-medium capitalize ring-1 ${tone}`}>
                          <Icon className="h-3 w-3" /> {e.action}
                        </span>
                        <span className="w-24 text-[12px] uppercase tracking-wide text-ink-faint">{e.category}</span>
                        <span className="font-mono text-[13px]">{e.key}</span>
                        {(e.old || e.new) && (
                          <span className="font-mono text-[12.5px] text-ink-muted">
                            {e.old && <span className="text-down line-through decoration-down/50">{e.old}</span>}
                            {e.old && e.new && " → "}
                            {e.new && <span className="text-up">{e.new}</span>}
                          </span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              ) : (
                <Empty>Nothing changed{cat !== "All changes" ? " of this kind" : ""} between these scans.</Empty>
              )}
            </>
          )}
        </Card>
      )}
    </div>
  );
}
