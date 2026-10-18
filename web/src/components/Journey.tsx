import { Bell, Briefcase, CheckCircle2, Database, Eye, Gauge, Rss, ShieldBan, Sparkles, type LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import type { JourneyStage } from "../lib/api";
import { ago, dateTime } from "../lib/format";

const ICON: Record<JourneyStage["key"], LucideIcon> = {
  reported: Rss,
  ingested: Database,
  scored: Gauge,
  enriched: Sparkles,
  seen: Eye,
  decided: CheckCircle2,
  acted: ShieldBan,
};

const STATE: Record<JourneyStage["state"], string> = {
  done: "bg-accent/15 text-accent-soft ring-accent/40",
  warn: "bg-down/15 text-down ring-down/40",
  none: "bg-card-2 text-ink-faint ring-line",
};

/** An indicator's path from feed to action: reported → ingested → scored →
 * enriched → seen in our environment → analyst decision → block or case. */
export default function Journey({ stages, compact = false }: { stages: JourneyStage[]; compact?: boolean }) {
  return (
    <ol className={compact ? "space-y-3" : "grid gap-3 sm:grid-cols-2 lg:grid-cols-4 2xl:grid-cols-7"}>
      {stages.map((st, i) => {
        const Icon = ICON[st.key] ?? Bell;
        return (
          <li key={st.key} className={`relative rounded-card border p-3 ${st.state === "none" ? "border-line/60 opacity-75" : st.state === "warn" ? "border-down/40" : "border-line"}`}>
            <p className="flex items-center gap-2">
              <span className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full ring-1 ${STATE[st.state]}`}>
                <Icon className="h-3.5 w-3.5" />
              </span>
              <span className="min-w-0">
                <span className="block text-[11px] uppercase tracking-wide text-ink-faint">Step {i + 1}</span>
                <span className="block truncate text-[13.5px] font-semibold">{st.title}</span>
              </span>
            </p>
            <p className="mt-1.5 text-[11.5px] text-ink-faint" title={st.at ? dateTime(st.at) : undefined}>
              {st.at ? `${dateTime(st.at)} · ${ago(st.at)}` : st.state === "none" ? "not yet" : ""}
            </p>
            <ul className="mt-1.5 space-y-0.5 text-[12.5px] text-ink-muted">
              {st.lines.map((l) => (
                <li key={l} className="break-words">
                  {l}
                </li>
              ))}
            </ul>
            {st.cases && st.cases.length > 0 && (
              <p className="mt-1.5 flex flex-wrap gap-1.5">
                {st.cases.map((c) => (
                  <Link key={c.id} to={`/cases/${c.id}`} className="inline-flex items-center gap-1 rounded bg-chip px-1.5 py-0.5 text-[12px] text-chip-ink ring-1 ring-line hover:text-accent-soft">
                    <Briefcase className="h-3 w-3" /> #{c.id}
                  </Link>
                ))}
              </p>
            )}
            {st.block && (
              <Link to="/blocklist" className="mt-1.5 inline-flex text-[12px] text-accent-soft hover:underline">
                Open the blocklist →
              </Link>
            )}
          </li>
        );
      })}
    </ol>
  );
}
