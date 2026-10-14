import { useState } from "react";
import { Link } from "react-router-dom";
import { Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { useApi } from "../lib/api";
import { usePage } from "../lib/page";

interface Matrix {
  families: number;
  peak: number;
  columns: { tactic: { id: string; name: string }; hits: number; cells: { id: string; name: string; count: number }[] }[];
}

/** Heat: none → faint card, then four steps of the accent blue. */
function heat(n: number, peak: number): string {
  if (!n) return "bg-card-2/50 text-ink-faint hover:text-ink-muted";
  const t = n / Math.max(1, peak);
  if (t > 0.75) return "bg-accent text-white";
  if (t > 0.5) return "bg-accent/70 text-white";
  if (t > 0.25) return "bg-accent/45 text-ink";
  return "bg-accent/25 text-ink";
}

export default function Attack() {
  usePage("Threat intel", "ATT&CK");
  const { data, error, reload } = useApi<Matrix>("attack");
  const [onlyUsed, setOnlyUsed] = useState(true);
  return (
    <div className="mx-auto w-full max-w-[1600px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead
          title="MITRE ATT&CK (Enterprise)"
          sub={data ? `Shaded by how many of the ${data.families} malware families your feeds point at use each technique` : "Techniques used by the malware your feeds see"}
        >
          <label className="flex items-center gap-2 text-[13px] text-ink-muted">
            <input type="checkbox" className="h-4 w-4 accent-[#1F6BFF]" checked={onlyUsed} onChange={(e) => setOnlyUsed(e.target.checked)} /> Only techniques in use
          </label>
        </CardHead>
        <div className="flex flex-wrap items-center gap-3 text-[12px] text-ink-muted">
          <span>Fewer families</span>
          {[0.2, 0.4, 0.6, 0.9].map((t) => (
            <span key={t} className={`h-3 w-6 rounded ${heat(t * 4, 4)}`} />
          ))}
          <span>more</span>
        </div>
      </Card>
      {error && !data ? (
        <Card>
          <Failed error={error} onRetry={reload} />
        </Card>
      ) : !data ? (
        <Skeleton className="h-96" />
      ) : !data.columns.length ? (
        <Card>
          <p className="text-ink-muted">The ATT&CK knowledge base isn't loaded yet; the worker loads it on its first run.</p>
        </Card>
      ) : (
        <div className="overflow-x-auto pb-2">
          <div className="flex min-w-max gap-3">
            {data.columns.map((col) => {
              const cells = onlyUsed ? col.cells.filter((c) => c.count) : col.cells;
              return (
                <section key={col.tactic.id} className="w-[176px] shrink-0">
                  <header className="card mb-2 px-3 py-2.5">
                    <Link to={`/entities/${col.tactic.id}`} className="block text-[13px] font-semibold leading-tight hover:text-accent-soft">
                      {col.tactic.name}
                    </Link>
                    <p className="mt-0.5 text-[11.5px] text-ink-faint">
                      {col.hits} of {col.cells.length} in use
                    </p>
                  </header>
                  <ul className="space-y-1.5">
                    {cells.map((c) => (
                      <li key={c.id}>
                        <Link
                          to={`/entities/${c.id}`}
                          title={`${c.id} ${c.name}: used by ${c.count} famil${c.count === 1 ? "y" : "ies"}`}
                          className={`block rounded-ctl px-2.5 py-1.5 text-[12px] leading-snug transition-colors ${heat(c.count, data.peak)}`}
                        >
                          <span className="block truncate">{c.name}</span>
                          <span className="flex justify-between text-[10.5px] opacity-75">
                            <span className="font-mono">{c.id}</span>
                            {c.count > 0 && <span>{c.count}</span>}
                          </span>
                        </Link>
                      </li>
                    ))}
                    {!cells.length && <li className="px-1 text-[12px] text-ink-faint">none in use</li>}
                  </ul>
                </section>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
