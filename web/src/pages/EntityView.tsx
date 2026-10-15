import { ExternalLink } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { Ioc } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { useV1 } from "../lib/api";
import { usePage } from "../lib/page";
import { plain } from "../lib/text";

interface Entity {
  stix_id: string;
  type: string;
  name: string;
  external_id: string | null;
  aliases: string[];
  platforms: string[];
  tactics: string[];
  is_subtechnique: boolean;
  revoked: boolean;
  deprecated: boolean;
  version: string | null;
  origin: string;
  url: string | null;
  description: string;
  relationship_counts: Record<string, number>;
}

interface GraphNode {
  ref: string;
  kind: string;
  type: string;
  label: string;
  external_id: string | null;
  extra: Record<string, unknown>;
}

interface Neighbors {
  total: number;
  items: { node: GraphNode; direction: "in" | "out"; edge: { rel_type: string; confidence: number; source: string | null; origin: string } }[];
}

const TYPE_LABEL: Record<string, string> = {
  malware: "Malware",
  tool: "Tool",
  "intrusion-set": "Threat actor",
  "attack-pattern": "Technique",
  "x-mitre-tactic": "Tactic",
  campaign: "Campaign",
  "course-of-action": "Mitigation",
  "x-mitre-data-source": "Data source",
};

function nodeHref(n: GraphNode): string | null {
  if (n.kind === "indicator") return `/indicators/${String(n.extra.id ?? "")}`;
  if (n.kind === "vulnerability") return `/vulnerabilities/${n.label}`;
  return `/entities/${encodeURIComponent(n.external_id ?? n.ref)}`;
}

function Group({ title, items }: { title: string; items: Neighbors["items"] }) {
  if (!items.length) return null;
  return (
    <Card className="!p-0">
      <div className="p-5 pb-3 sm:p-6 sm:pb-3">
        <CardHead title={`${title} (${items.length})`} />
      </div>
      <ul className="grid gap-px border-t border-line bg-line sm:grid-cols-2 xl:grid-cols-3">
        {items.slice(0, 60).map((i) => {
          const href = nodeHref(i.node);
          const inner = (
            <>
              {i.node.kind === "indicator" ? <Ioc value={i.node.label} className="text-[13px]" /> : <span className="text-[13.5px]">{i.node.label}</span>}
              <span className="block text-[11.5px] text-ink-faint">
                {i.node.external_id ? `${i.node.external_id} · ` : ""}
                {i.edge.rel_type.replace(/-/g, " ")}
                {i.edge.source ? ` · ${i.edge.source}` : ""}
              </span>
            </>
          );
          return (
            <li key={`${i.node.ref}-${i.edge.rel_type}`} className="bg-card">
              {href ? (
                <Link to={href} className="block px-5 py-3 hover:bg-row-hover">
                  {inner}
                </Link>
              ) : (
                <div className="px-5 py-3">{inner}</div>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

export default function EntityView() {
  const { ref = "" } = useParams();
  const ent = useV1<Entity>(`entities/${encodeURIComponent(ref)}`);
  const nb = useV1<Neighbors>("graph/neighbors", { node: ref, limit: 500 });
  usePage("Threat intel", "ATT&CK", ent.data?.name ?? ref);
  const e = ent.data;
  if (ent.error && !e) {
    return (
      <div className="mx-auto max-w-[1320px] px-4 py-8 sm:px-6 lg:px-8">
        <Card>
          <Failed error={ent.error.startsWith("404") ? `${ref} isn't in the knowledge base` : ent.error} onRetry={ent.reload} />
        </Card>
      </div>
    );
  }
  const items = nb.data?.items ?? [];
  const by = (pred: (i: Neighbors["items"][number]) => boolean) => items.filter(pred);
  const techniques = by((i) => i.node.type === "attack-pattern");
  const actors = by((i) => i.node.type === "intrusion-set" || i.node.type === "campaign");
  const software = by((i) => i.node.type === "malware" || i.node.type === "tool");
  const indicators = by((i) => i.node.kind === "indicator");
  const vulns = by((i) => i.node.kind === "vulnerability");
  const mitigations = by((i) => i.node.type === "course-of-action");

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        {!e ? (
          <Skeleton className="h-28" />
        ) : (
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="min-w-0 max-w-4xl">
              <p className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-muted">
                <span className="rounded bg-tint px-2 py-0.5 font-medium text-accent-soft">{TYPE_LABEL[e.type] ?? e.type}</span>
                {e.external_id && <span className="font-mono">{e.external_id}</span>}
                {e.revoked && <span className="text-down">revoked</span>}
                {e.deprecated && <span className="text-warn">deprecated</span>}
                {e.version && <span className="text-ink-faint">v{e.version}</span>}
              </p>
              <h1 className="text-[24px] font-bold">{e.name}</h1>
              {e.aliases.length > 1 && <p className="mt-1 text-[13px] text-ink-muted">Also known as {e.aliases.filter((a) => a !== e.name).slice(0, 10).join(", ")}</p>}
              <p className="mt-3 whitespace-pre-line text-[13.5px] leading-relaxed text-ink-muted">{plain(e.description) || "No description."}</p>
              {(e.platforms.length > 0 || e.tactics.length > 0) && (
                <p className="mt-3 flex flex-wrap gap-1.5">
                  {[...e.tactics, ...e.platforms].map((t) => (
                    <span key={t} className="rounded bg-chip px-2 py-0.5 text-[12px] text-chip-ink ring-1 ring-line">{t}</span>
                  ))}
                </p>
              )}
            </div>
            {e.url && (
              <a href={e.url} target="_blank" rel="noopener noreferrer" className="btn-ghost h-9">
                MITRE page <ExternalLink className="h-3.5 w-3.5" />
              </a>
            )}
          </div>
        )}
      </Card>

      {nb.error && !nb.data ? (
        <Card><Failed error={nb.error} onRetry={nb.reload} /></Card>
      ) : !nb.data ? (
        <Skeleton className="h-40" />
      ) : !items.length ? (
        <Card><Empty>No links to other intel yet.</Empty></Card>
      ) : (
        <>
          <Group title="Indicators pointing at it" items={indicators} />
          <Group title="Techniques" items={techniques} />
          <Group title="Threat actors and campaigns" items={actors} />
          <Group title="Malware and tools" items={software} />
          <Group title="Vulnerabilities" items={vulns} />
          <Group title="Mitigations" items={mitigations} />
        </>
      )}
    </div>
  );
}
