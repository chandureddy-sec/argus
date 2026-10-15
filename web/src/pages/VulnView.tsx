import { ExternalLink, ShieldAlert } from "lucide-react";
import { useParams } from "react-router-dom";
import { AddToCase } from "../components/actions";
import { Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { useV1, type Me } from "../lib/api";
import { date } from "../lib/format";
import { usePage } from "../lib/page";
import { plain } from "../lib/text";
import { cvssTone, PRIO_TONE, type VulnRow } from "./Vulnerabilities";

interface VulnDetail extends VulnRow {
  cvss_vector: string | null;
  cvss_version: string | null;
  cwes: string[];
  products: { vendor: string; product: string; version?: string }[];
  references: { url: string; tags?: string[]; source?: string }[];
  kev_due_date: string | null;
  kev_ransomware: string | null;
  kev_name: string | null;
  kev_required_action: string | null;
  epss_date: string | null;
  osv_ids: string[];
  packages: { ecosystem?: string; name?: string }[];
  patch_breakdown: { score?: number; floor?: string | null; reasons?: { points: number; reason: string }[] } | null;
}

const PRIO_WORDS: Record<string, string> = { P1: "Patch now", P2: "Patch this week", P3: "Patch this month", P4: "Routine" };

export default function VulnView({ me }: { me?: Me }) {
  const { cve = "" } = useParams();
  usePage("Threat intel", "Vulnerabilities", cve);
  const { data: v, error, reload } = useV1<VulnDetail>(`vulnerabilities/${encodeURIComponent(cve)}`);
  const analyst = me?.role === "admin" || me?.role === "analyst";

  if (error && !v) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Failed error={error.startsWith("404") ? `${cve} isn't in the knowledge base` : error} onRetry={reload} />
        </Card>
      </div>
    );
  }
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        {!v ? (
          <Skeleton className="h-28" />
        ) : (
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="min-w-0 flex-1">
              <p className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-muted">
                Published {date(v.published)}
                {v.kev && <span className="rounded bg-down/15 px-1.5 py-0.5 font-semibold text-down">Known exploited · KEV {date(v.kev_date_added)}</span>}
                {v.kev_ransomware === "Known" && <span className="rounded bg-down/15 px-1.5 py-0.5 font-semibold text-down">used by ransomware</span>}
              </p>
              <h1 className="font-mono text-[24px] font-bold">{v.cve_id}</h1>
              {v.kev_name && <p className="mt-1 text-[14px] text-ink">{v.kev_name}</p>}
              <p className="mt-3 max-w-4xl text-[13.5px] leading-relaxed text-ink-muted">{plain(v.description) || "No description yet."}</p>
            </div>
            <div className="grid grid-cols-3 gap-3 text-center">
              <div className="rounded-ctl border border-line bg-card-2/40 px-4 py-3">
                <p className="label">Priority</p>
                <p className={`mt-1 rounded px-2 text-[20px] font-bold ${PRIO_TONE[v.patch_priority ?? "P4"] ?? ""}`}>{v.patch_priority ?? "–"}</p>
              </div>
              <div className="rounded-ctl border border-line bg-card-2/40 px-4 py-3">
                <p className="label">CVSS</p>
                <p className={`mt-1 text-[20px] font-bold tabular-nums ${cvssTone(v.cvss_score)}`}>{v.cvss_score?.toFixed(1) ?? "–"}</p>
              </div>
              <div className="rounded-ctl border border-line bg-card-2/40 px-4 py-3" title="Probability of exploitation in the next 30 days">
                <p className="label">EPSS</p>
                <p className="mt-1 text-[20px] font-bold tabular-nums">{v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "–"}</p>
              </div>
            </div>
          </div>
        )}
        {v && analyst && (
          <div className="mt-5 border-t border-line pt-5">
            <AddToCase cve={v.cve_id} />
          </div>
        )}
      </Card>

      <div className="grid gap-6 xl:grid-cols-2">
        <Card>
          <CardHead title={v?.patch_priority ? PRIO_WORDS[v.patch_priority] : "Patch priority"} sub="How the priority was reached" />
          {!v ? (
            <Skeleton className="h-32" />
          ) : (
            <div className="space-y-3">
              <ul className="space-y-2">
                {(v.patch_breakdown?.reasons ?? []).map((r) => (
                  <li key={r.reason} className="flex items-center justify-between gap-3 rounded-ctl border border-line bg-card-2/40 px-3 py-2 text-[13px]">
                    <span>{r.reason}</span>
                    <b className="tabular-nums">+{r.points}</b>
                  </li>
                ))}
              </ul>
              {v.patch_breakdown?.floor && (
                <p className="flex items-center gap-2 text-[13px] text-warn">
                  <ShieldAlert className="h-4 w-4" /> {v.patch_breakdown.floor}
                </p>
              )}
              {v.kev_required_action && (
                <p className="rounded-ctl border border-down/30 bg-down/[0.05] p-3 text-[13px]">
                  <b>CISA required action</b>: {v.kev_required_action}
                  {v.kev_due_date && <span className="text-ink-muted"> (due {date(v.kev_due_date)})</span>}
                </p>
              )}
            </div>
          )}
        </Card>
        <Card>
          <CardHead title="What it affects" />
          {!v ? (
            <Skeleton className="h-32" />
          ) : (
            <dl className="grid grid-cols-[120px_1fr] gap-x-4 gap-y-2 text-[13px]">
              <dt className="text-ink-faint">Products</dt>
              <dd className="text-ink-muted">{v.products.length ? v.products.slice(0, 12).map((p) => `${p.vendor} ${p.product}`.replace(/_/g, " ")).join(", ") : "–"}</dd>
              <dt className="text-ink-faint">Weakness</dt>
              <dd className="text-ink-muted">{v.cwes.join(", ") || "–"}</dd>
              {v.cvss_vector && (
                <>
                  <dt className="text-ink-faint">CVSS vector</dt>
                  <dd className="break-all font-mono text-[12px] text-ink-muted">{v.cvss_vector}</dd>
                </>
              )}
              {v.osv_ids.length > 0 && (
                <>
                  <dt className="text-ink-faint">Advisories</dt>
                  <dd className="text-ink-muted">{v.osv_ids.join(", ")}</dd>
                </>
              )}
              {v.packages.length > 0 && (
                <>
                  <dt className="text-ink-faint">Packages</dt>
                  <dd className="text-ink-muted">{v.packages.slice(0, 10).map((p) => `${p.ecosystem ?? ""}/${p.name ?? ""}`).join(", ")}</dd>
                </>
              )}
            </dl>
          )}
        </Card>
      </div>

      {v?.references.length ? (
        <Card>
          <CardHead title="References" sub="Vendor advisories, patches and write-ups (open in a new tab)" />
          <ul className="space-y-1.5">
            {v.references.slice(0, 30).map((r) => (
              <li key={r.url} className="flex items-center gap-2 text-[13px]">
                <a href={r.url} target="_blank" rel="noopener noreferrer" className="min-w-0 truncate text-accent-soft hover:underline">
                  {r.url}
                </a>
                <ExternalLink className="h-3 w-3 shrink-0 text-ink-faint" />
                {r.tags?.slice(0, 3).map((t) => (
                  <span key={t} className="shrink-0 rounded bg-chip px-1.5 text-[11px] text-chip-ink">{t}</span>
                ))}
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
    </div>
  );
}
