import { Crosshair, ExternalLink, X } from "lucide-react";
import { useEffect } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { useApi, type Indicator, type IndicatorRelated } from "../lib/api";
import { TYPE_LABEL, verdictOf } from "../lib/ioc";
import { Ioc, Score, TlpTag, VerdictPill } from "./intel";
import Journey from "./Journey";
import { Failed, Skeleton } from "./states";

/** A side panel with one indicator's threat journey, opened from a list row. */
export default function JourneyDrawer({ ind, onClose }: { ind: Indicator; onClose: () => void }) {
  const { data, error, reload } = useApi<IndicatorRelated>(`indicators/${ind.id}/related`);
  useEffect(() => {
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", esc);
    return () => window.removeEventListener("keydown", esc);
  }, [onClose]);
  const verdict = ind.status === "false_positive" ? "benign" : verdictOf(ind.priority_score);
  const pivots = data?.groups.flatMap((g) => g.items.map((p) => ({ ...p, group: g.name }))).slice(0, 12) ?? [];
  return createPortal(
    <div className="fixed inset-0 z-50 flex justify-end bg-scrim/60" onClick={onClose} role="dialog" aria-modal="true" aria-label="Threat journey">
      <aside className="flex h-full w-full max-w-[520px] flex-col overflow-y-auto border-l border-line bg-card shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <header className="sticky top-0 z-10 border-b border-line bg-card p-5">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="mb-1.5 flex flex-wrap items-center gap-2 text-[12px] text-ink-muted">
                {TYPE_LABEL[ind.type] ?? ind.type} <TlpTag tlp={ind.tlp} /> <VerdictPill verdict={verdict} />
              </p>
              <h2 className="break-all text-[16px] font-semibold">
                <Ioc value={ind.defanged} />
              </h2>
            </div>
            <button className="btn-ghost h-8 w-8 shrink-0 !px-0" onClick={onClose} aria-label="Close">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="mt-3 flex flex-wrap items-center gap-2">
            <Score n={ind.priority_score} />
            <Link to={`/indicators/${ind.id}`} className="btn-primary h-8 text-[13px]">
              <ExternalLink className="h-4 w-4" /> Open full page
            </Link>
            <Link to={`/verify?q=${encodeURIComponent(ind.defanged)}`} className="btn-ghost h-8 text-[13px]">
              <Crosshair className="h-4 w-4" /> Verify now
            </Link>
          </div>
        </header>
        <div className="space-y-5 p-5">
          <section>
            <p className="label mb-2">Threat journey: feed to action</p>
            {error && !data ? <Failed error={error} onRetry={reload} /> : data ? <Journey stages={data.journey} compact /> : <Skeleton className="h-64" />}
          </section>
          {pivots.length > 0 && (
            <section>
              <p className="label mb-2">Linked to</p>
              <div className="flex flex-wrap gap-1.5">
                {pivots.map((p) => (
                  <Link key={p.ref} to={p.href} title={`${p.group} · ${p.rel}${p.source ? ` · ${p.source}` : ""}`} className="rounded bg-chip px-2 py-1 text-[12.5px] text-chip-ink ring-1 ring-line hover:text-accent-soft">
                    {p.id && <span className="mr-1 font-mono text-[11.5px] text-ink-faint">{p.id}</span>}
                    {p.label}
                  </Link>
                ))}
              </div>
            </section>
          )}
        </div>
      </aside>
    </div>,
    document.body,
  );
}
