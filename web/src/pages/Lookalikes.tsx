import { Check, Loader2, Radar, ShieldBan, X } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { Ioc } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { send, useV1, type Me } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

interface Evidence {
  source: "ct" | "feed";
  first_certificate?: string;
  indicator?: number;
}

interface Row {
  id: number;
  domain: string;
  candidate: string;
  fuzzer: string;
  firstSeen: string;
  lastSeen: string;
  evidence: Evidence[];
  status: "new" | "confirmed" | "benign";
  reviewedBy: string | null;
  reviewedAt: string | null;
  block?: number;
  blockError?: string;
}

const FILTERS = ["New", "Confirmed", "Benign", "All"] as const;
const TECHNIQUE: Record<string, string> = {
  keyword: "brand keyword (combosquatting)",
  "tld-swap": "another top-level domain",
  homoglyph: "look-alike characters",
  bitsquatting: "one bit flipped",
  transposition: "swapped letters",
  omission: "a letter left out",
  insertion: "a letter added",
  repetition: "a letter doubled",
  replacement: "a neighbouring key",
  hyphenation: "a hyphen added",
  subdomain: "a dot added",
  vowelswap: "a vowel swapped",
  addition: "a letter appended",
  dictionary: "a word added",
};

function Seen({ e }: { e: Evidence }) {
  if (e.source === "ct") return <span>certificate {e.first_certificate ? `since ${e.first_certificate.slice(0, 10)}` : "logged"}</span>;
  return (
    <span>
      in our feeds (<Link className="underline" to={`/indicators/${e.indicator}`}>indicator #{e.indicator}</Link>)
    </span>
  );
}

export default function Lookalikes({ me }: { me?: Me }) {
  usePage("Threat intel", "Lookalike domains");
  const [filter, setFilter] = useState<(typeof FILTERS)[number]>("New");
  const status = filter === "All" ? undefined : filter.toLowerCase();
  const { data, error, reload } = useV1<{ domains: string[]; items: Row[] }>("lookalikes", status ? { status } : {});
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<string>();
  const analyst = me?.role === "admin" || me?.role === "analyst";

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    setMsg(undefined);
    try {
      setMsg(await fn());
      reload();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const scan = () =>
    act("scan", async () => {
      const r = await send<{ candidates: number; new: number; errors: string[] }>("POST", "/api/v1/lookalikes/scan");
      return `${r.candidates} lookalike(s) found, ${r.new} new.${r.errors.length ? ` Problems: ${r.errors.join("; ")}` : ""}`;
    });
  const review = (r: Row, next: "confirmed" | "benign", block = false) =>
    act(`${next}${r.id}`, async () => {
      const x = await send<Row>("POST", `/api/v1/lookalikes/${r.id}/review`, { status: next, block });
      if (x.block) return `${r.candidate} confirmed and added to the blocklist (#${x.block}, monitor mode).`;
      if (x.blockError) return `${r.candidate} confirmed, but not blocked: ${x.blockError}`;
      return `${r.candidate} marked ${next}.`;
    });

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card className="!p-0">
        <div className="flex flex-wrap items-start justify-between gap-3 p-5 pb-3 sm:p-6 sm:pb-3">
          <CardHead
            title="Domains imitating ours"
            sub={`Typos, look-alike characters, other TLDs and brand combinations of ${data?.domains.join(", ") || "the org profile's domains"}, found passively in Certificate Transparency logs and our own feeds. Nothing is resolved or contacted. Checked daily.`}
          />
          <div className="flex items-center gap-2">
            <Segmented label="Status" value={filter} options={FILTERS} onChange={setFilter} />
            {analyst && (
              <button className="btn-primary h-9" disabled={!!busy} onClick={scan}>
                {busy === "scan" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />} Scan now
              </button>
            )}
          </div>
        </div>
        {msg && <p role="status" className="px-5 pb-3 text-[13px] text-ink-muted sm:px-6">{msg}</p>}
        {error && !data ? (
          <Failed error={error} onRetry={reload} />
        ) : !data ? (
          <Skeleton className="mx-6 mb-6 h-24" />
        ) : !data.domains.length ? (
          <Empty>Add your domains to the org profile (org.domains) to watch for lookalikes.</Empty>
        ) : !data.items.length ? (
          <Empty>No {filter === "All" ? "" : filter.toLowerCase() + " "}lookalikes.</Empty>
        ) : (
          <ul className="divide-y divide-line border-t border-line">
            {data.items.map((r) => (
              <li key={r.id} className="grid gap-2 px-5 py-3 sm:grid-cols-[1fr_auto] sm:px-6">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2">
                    <Ioc value={r.candidate} className="font-medium" />
                    <span className="text-[12px] text-ink-muted">imitates {r.domain} by {TECHNIQUE[r.fuzzer] ?? r.fuzzer}</span>
                  </p>
                  <p className="text-[12.5px] text-ink-muted">
                    Seen: {r.evidence.map((e, i) => (
                      <span key={i}>
                        {i > 0 && " · "}
                        <Seen e={e} />
                      </span>
                    ))}{" "}
                    · first found {ago(r.firstSeen)}
                    {r.reviewedBy && ` · ${r.status} by ${r.reviewedBy} ${ago(r.reviewedAt)}`}
                  </p>
                </div>
                {analyst && r.status === "new" && (
                  <div className="flex flex-wrap items-center gap-2">
                    <button className="btn-ghost h-8 text-[13px]" disabled={!!busy} onClick={() => review(r, "confirmed", true)} title="Confirm and add it to the blocklist in monitor mode">
                      <ShieldBan className="h-4 w-4" /> Confirm & block
                    </button>
                    <button className="btn-ghost h-8 text-[13px]" disabled={!!busy} onClick={() => review(r, "confirmed")}>
                      <Check className="h-4 w-4" /> Confirm
                    </button>
                    <button className="btn-ghost h-8 text-[13px]" disabled={!!busy} onClick={() => review(r, "benign")} title="Ours, a partner's, or harmless">
                      <X className="h-4 w-4" /> Benign
                    </button>
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
