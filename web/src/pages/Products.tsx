import { FileDown, FileText, Loader2, Play, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { TlpTag } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { send, useV1, type Me } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

interface Product {
  id: number;
  kind: "daily" | "weekly" | "vulns" | "exec";
  title: string;
  periodStart: string;
  periodEnd: string;
  tlp: string;
  sha256: string;
  generatedBy: string;
  createdAt: string;
}

const KINDS: [Product["kind"], string, string][] = [
  ["daily", "Daily threat brief", "Yesterday: new high-priority indicators, malware families, exploited CVEs, cases, lookalike domains"],
  ["weekly", "Weekly CTI report", "Last Monday-to-Monday week, with the week before for comparison"],
  ["vulns", "Vulnerability priority list", "P1/P2 vulnerabilities, ours first, with why"],
  ["exec", "Executive one-pager", "Plain-language risks and actions for last week"],
];
const FILTERS = ["All", "Daily", "Weekly", "Vulnerabilities", "Executive"] as const;
const FILTER_KIND: Record<(typeof FILTERS)[number], Product["kind"] | undefined> = {
  All: undefined,
  Daily: "daily",
  Weekly: "weekly",
  Vulnerabilities: "vulns",
  Executive: "exec",
};

function day(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
}

export default function Products({ me }: { me?: Me }) {
  usePage("Threat intel", "Products");
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("All");
  const kind = FILTER_KIND[filter];
  const { data, error, reload } = useV1<Product[]>("products", kind ? { kind } : {});
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const analyst = me?.role === "admin" || me?.role === "analyst";

  const generate = async (k: Product["kind"]) => {
    setBusy(k);
    setMsg(undefined);
    try {
      const p = await send<Product>("POST", "/api/v1/products/generate", { kind: k });
      setMsg(`${p.title} for ${day(p.periodStart)} – ${day(p.periodEnd)} generated (${p.tlp}).`);
      reload();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const verify = async (p: Product) => {
    setBusy(`v${p.id}`);
    setMsg(undefined);
    try {
      const r = await send<{ match: boolean; rebuilt: string }>("POST", `/api/v1/products/${p.id}/verify`);
      setMsg(
        r.match
          ? `${p.title} #${p.id}: rebuilding it from the database gives the same fingerprint (${p.sha256.slice(0, 16)}).`
          : `${p.title} #${p.id}: the data changed since it was generated (now ${r.rebuilt.slice(0, 16)}); generate it again to refresh it.`,
      );
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead
          title="Intelligence products"
          sub="Built from stored records only, so the same data always gives the same product (fingerprinted). Every item links to its record; content is capped at TLP:GREEN unless configured otherwise. The worker builds them daily at 06:05 UTC."
        />
        <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          {KINDS.map(([k, title, sub]) => (
            <li key={k} className="flex flex-col rounded-ctl border border-line bg-card-2/30 p-4">
              <p className="font-medium">{title}</p>
              <p className="mb-3 flex-1 text-[12.5px] text-ink-muted">{sub}</p>
              {analyst && (
                <button className="btn-ghost h-8 self-start text-[13px]" disabled={!!busy} onClick={() => generate(k)}>
                  {busy === k ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Generate now
                </button>
              )}
            </li>
          ))}
        </ul>
        {msg && <p role="status" className="mt-3 text-[13px] text-ink-muted">{msg}</p>}
      </Card>
      <Card className="!p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead title="Library" sub="Within your clearance" />
          <Segmented label="Kind" value={filter} options={FILTERS} onChange={setFilter} />
        </div>
        {error && !data ? (
          <Failed error={error} onRetry={reload} />
        ) : !data ? (
          <Skeleton className="mx-6 mb-6 h-24" />
        ) : !data.length ? (
          <Empty>No products yet{analyst ? ": generate one above." : "."}</Empty>
        ) : (
          <ul className="divide-y divide-line border-t border-line">
            {data.map((p) => (
              <li key={p.id} className="flex flex-wrap items-center gap-3 px-5 py-3 sm:px-6">
                <div className="min-w-0 flex-1">
                  <p className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{p.title}</span> <TlpTag tlp={p.tlp} />
                  </p>
                  <p className="text-[12.5px] text-ink-muted">
                    {p.kind === "vulns" ? `as of ${day(p.periodEnd)}` : `${day(p.periodStart)} – ${day(p.periodEnd)}`} · generated {ago(p.createdAt)} by {p.generatedBy} ·{" "}
                    <span className="font-mono" title={p.sha256}>{p.sha256.slice(0, 12)}</span>
                  </p>
                </div>
                <a className="btn-ghost h-8 text-[13px]" href={`/api/v1/products/${p.id}/html`} target="_blank" rel="noopener noreferrer">
                  <FileText className="h-4 w-4" /> Open
                </a>
                <a className="btn-ghost h-8 text-[13px]" href={`/api/v1/products/${p.id}/pdf`}>
                  <FileDown className="h-4 w-4" /> PDF
                </a>
                <button className="btn-ghost h-8 text-[13px]" disabled={!!busy} onClick={() => verify(p)} title="Rebuild it from the database and compare fingerprints">
                  {busy === `v${p.id}` ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Verify
                </button>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
