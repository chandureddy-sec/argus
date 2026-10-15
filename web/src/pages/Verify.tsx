import { Briefcase, ExternalLink, Globe, Loader2, Lock, Network, Search, ShieldOff } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { AddToCase, BlockButton, FlagButtons } from "../components/actions";
import { CopyButton, Ioc, Score, TlpSelect, TlpTag, VerdictPill } from "../components/intel";
import { Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { readEvents, type Card as ProviderCard, type InternalResult, type Local, type Me, type QueryInfo, type VerifyDone, type VerifyEvent } from "../lib/api";
import { ago, date } from "../lib/format";
import { usePage } from "../lib/page";

const TONE: Record<string, string> = {
  mal: "border-down/40 bg-down/[0.05]",
  sus: "border-warn/40 bg-warn/[0.04]",
  ok: "border-up/30 bg-up/[0.03]",
  info: "border-line bg-card",
  off: "border-line bg-card opacity-70",
};
const DOT: Record<string, string> = { mal: "bg-down", sus: "bg-warn", ok: "bg-up", info: "bg-info-soft", off: "bg-ink-faint" };

function ProviderView({ c }: { c: ProviderCard }) {
  return (
    <article className={`animate-rise rounded-card border p-4 ${TONE[c.tone] ?? TONE.info}`}>
      <header className="mb-2 flex items-center justify-between gap-2">
        <h3 className="flex items-center gap-2 text-[14px] font-semibold">
          <span className={`h-2 w-2 rounded-full ${DOT[c.tone] ?? DOT.info}`} />
          {c.title}
        </h3>
        <span className="text-[11.5px] text-ink-faint">
          {c.status === "cached" ? `saved ${ago(c.fetchedAt)}` : c.status === "stale" ? "last known answer" : c.status === "ok" ? "just now" : ""}
          {c.mode === "active" && " · contacts the target"}
        </span>
      </header>
      <p className="text-[13.5px] font-medium text-ink">
        <Ioc value={c.headline} mono={false} />
      </p>
      {c.rows.length > 0 && (
        <dl className="mt-3 grid grid-cols-[minmax(110px,auto)_1fr] gap-x-3 gap-y-1 text-[12.5px]">
          {c.rows.map(([k, v]) => (
            <div key={k} className="contents">
              <dt className="text-ink-faint">{k}</dt>
              <dd className="min-w-0 text-ink-muted">
                {Array.isArray(v) ? v.map((x) => <span key={x} className="block break-all"><Ioc value={x} mono={false} /></span>) : <Ioc value={String(v)} mono={false} />}
              </dd>
            </div>
          ))}
        </dl>
      )}
      {c.evidence.length > 0 && (
        <ul className="mt-3 space-y-1 text-[12.5px]">
          {c.evidence.map((ev, i) => (
            <li key={i} className="flex gap-2">
              <span className={`shrink-0 rounded px-1.5 text-[11px] font-semibold ${ev.kind === "malicious" ? "bg-down/15 text-down" : ev.kind === "suspicious" ? "bg-warn/15 text-warn" : "bg-up/15 text-up"}`}>{ev.kind}</span>
              <span className="text-ink-muted"><Ioc value={ev.text} mono={false} /></span>
            </li>
          ))}
        </ul>
      )}
      {c.error && <p className="mt-2 text-[12px] text-warn">No answer this time ({c.error}), so this is the last one we saved.</p>}
    </article>
  );
}

function OurIntel({ local }: { local: Local }) {
  const k = local.known;
  return (
    <article className={`rounded-card border p-4 ${k && (k.priority_score ?? 0) >= 60 ? TONE.mal : k && (k.priority_score ?? 0) >= 30 ? TONE.sus : TONE.info}`}>
      <header className="mb-2 flex items-center justify-between">
        <h3 className="text-[14px] font-semibold">Our intel</h3>
        {k && (
          <Link to={`/indicators/${k.indicator_id}`} className="text-[12.5px] text-accent-soft hover:underline">
            Open indicator →
          </Link>
        )}
      </header>
      {k ? (
        <>
          <p className="text-[13.5px] font-medium">{k.sources.length ? `Reported by ${k.sources.join(", ")}` : "Flagged by an analyst"}</p>
          <dl className="mt-3 grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
            <dt className="text-ink-faint">Score</dt>
            <dd><Score n={k.priority_score} /></dd>
            <dt className="text-ink-faint">Status</dt>
            <dd className="text-ink-muted">{k.status.replace("_", " ")}</dd>
            <dt className="text-ink-faint">First seen</dt>
            <dd className="text-ink-muted">{date(k.first_seen)}</dd>
            <dt className="text-ink-faint">Last seen</dt>
            <dd className="text-ink-muted">{ago(k.last_seen)}</dd>
            {k.analyst_verdict && (
              <>
                <dt className="text-ink-faint">Analyst</dt>
                <dd className="text-ink-muted">{k.analyst_verdict === "tp" ? "confirmed malicious" : "not malicious"} ({k.analyst_verdict_by})</dd>
              </>
            )}
          </dl>
        </>
      ) : (
        <p className="text-[13.5px] text-ink-muted">Not in our intel yet: no feed has reported it.</p>
      )}
      {local.asset && (
        <p className="mt-3 rounded-ctl bg-tint px-2.5 py-1.5 text-[12.5px] text-accent-soft">
          Our asset ({local.asset.kind} of <Ioc value={local.asset.target} mono={false} />): investigate it, don't block it.
        </p>
      )}
      {local.allowlist?.effect && <p className="mt-2 text-[12.5px] text-ink-muted">{local.allowlist.effect === "suppress" ? "Allowlisted" : "Known service"}: {local.allowlist.reasons.join("; ")}</p>}
      {local.related.length > 0 && (
        <p className="mt-3 flex flex-wrap gap-1.5">
          {local.related.map((r) => (
            <Link key={r.ref} to={`/entities/${encodeURIComponent(r.ref)}`} className="rounded bg-chip px-2 py-0.5 text-[12px] text-chip-ink ring-1 ring-line hover:text-accent-soft">
              {r.label}
            </Link>
          ))}
        </p>
      )}
    </article>
  );
}

const SEVERITY_TONE: Record<string, string> = {
  critical: "bg-down/15 text-down",
  high: "bg-down/12 text-down",
  medium: "bg-warn/15 text-warn",
  low: "bg-chip text-chip-ink",
};

/** Verify on a private or reserved address: what it is and what we hold, from our own data only. */
function InternalView({ r }: { r: InternalResult }) {
  const leaked = r.publicNames.length > 0;
  return (
    <>
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-5">
          <div className="min-w-0 flex-1">
            <p className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-muted">
              {r.query.typeLabel}
              <span className="inline-flex items-center gap-1.5 rounded-full bg-chip px-2.5 py-0.5 text-[12px] font-semibold text-chip-ink ring-1 ring-line">
                <Lock className="h-3 w-3" /> {r.range.label}
              </span>
            </p>
            <h2 className="text-[22px] font-semibold"><Ioc value={r.query.value} /></h2>
            <p className="mt-2 text-[12.5px] text-ink-faint">Checked against our own data only. Nothing was sent to a provider or a public site.</p>
          </div>
          <div className="max-w-md rounded-card border border-line bg-card-2/40 p-4">
            <p className="label">Why no reputation</p>
            <p className="mt-1 text-[13px] text-ink-muted">
              Threat intel only judges public addresses: this range is used inside millions of networks, so a provider's verdict would mean nothing, and asking would describe your network to them.
            </p>
          </div>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-line pt-5">
          <CopyButton value={r.query.value} />
        </div>
      </Card>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <article className="rounded-card border border-line bg-card p-4">
          <h3 className="mb-2 flex items-center gap-2 text-[14px] font-semibold"><Network className="h-4 w-4 text-ink-muted" /> What this address is</h3>
          <p className="text-[13.5px] font-medium text-ink">{r.range.label}{r.range.standard && <span className="font-normal text-ink-muted"> · {r.range.standard}</span>}</p>
          <p className="mt-1 text-[12.5px] text-ink-muted"><Ioc value={r.range.note} mono={false} /></p>
          <dl className="mt-3 grid grid-cols-[110px_1fr] gap-x-3 gap-y-1 text-[12.5px]">
            <dt className="text-ink-faint">Range</dt>
            <dd className="text-ink-muted"><Ioc value={r.range.network} /></dd>
            <dt className="text-ink-faint">Subnet</dt>
            <dd className="text-ink-muted"><Ioc value={r.subnet} /></dd>
          </dl>
        </article>

        <article className={`rounded-card border p-4 ${leaked ? "border-warn/40 bg-warn/[0.04]" : "border-line bg-card"}`}>
          <h3 className="mb-2 flex items-center gap-2 text-[14px] font-semibold">
            <span className={`h-2 w-2 rounded-full ${leaked ? "bg-warn" : "bg-up"}`} /> <Globe className="h-4 w-4 text-ink-muted" /> Public DNS
          </h3>
          {leaked ? (
            <>
              <p className="text-[13.5px] font-medium text-ink">Published in public DNS by {r.publicNames.length === 1 ? "1 name" : `${r.publicNames.length} names`}</p>
              <p className="mt-1 text-[12.5px] text-ink-muted">Anyone can look these up and learn part of your internal layout. Serve internal names from internal DNS only (split-horizon).</p>
              <ul className="mt-3 space-y-1 text-[12.5px]">
                {r.publicNames.map((h) => (
                  <li key={h.assetId} className="flex flex-wrap items-baseline justify-between gap-x-3">
                    <Ioc value={h.name} className="text-ink" />
                    <span className="text-ink-faint">scan of <Ioc value={h.target} mono={false} /> · {ago(h.lastSeen)}</span>
                  </li>
                ))}
              </ul>
            </>
          ) : (
            <>
              <p className="text-[13.5px] font-medium text-ink">Not in public DNS</p>
              <p className="mt-1 text-[12.5px] text-ink-muted">No public name from your ReconX scans resolves to it.</p>
            </>
          )}
          {r.nearbyNames.length > 0 && (
            <div className="mt-3 border-t border-line pt-3">
              <p className="text-[12px] text-ink-faint">Also pointing into <Ioc value={r.subnet} mono={false} /></p>
              <ul className="mt-1 space-y-1 text-[12.5px]">
                {r.nearbyNames.map((h) => (
                  <li key={h.assetId} className="flex flex-wrap items-baseline justify-between gap-x-3">
                    <Ioc value={h.name} className="text-ink-muted" />
                    <span className="text-ink-faint"><Ioc value={(h.ips ?? []).join(", ")} /></span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </article>

        <article className="rounded-card border border-line bg-card p-4">
          <h3 className="mb-2 flex items-center gap-2 text-[14px] font-semibold"><Briefcase className="h-4 w-4 text-ink-muted" /> Cases</h3>
          {r.cases.length ? (
            <ul className="space-y-2 text-[12.5px]">
              {r.cases.map((c) => (
                <li key={c.id}>
                  <Link to={`/cases/${c.id}`} className="flex items-center justify-between gap-3 rounded-ctl px-2 py-1.5 hover:bg-row-hover">
                    <span className="min-w-0 truncate text-ink">#{c.id} <Ioc value={c.title} mono={false} /></span>
                    <span className="flex shrink-0 items-center gap-1.5">
                      <span className={`rounded px-1.5 text-[11px] font-semibold ${SEVERITY_TONE[c.severity] ?? SEVERITY_TONE.low}`}>{c.severity}</span>
                      <span className="text-ink-faint">{c.status}</span>
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-[13px] text-ink-muted">No case you can read mentions it.</p>
          )}
        </article>

        <article className="rounded-card border border-line bg-card p-4">
          <h3 className="mb-2 flex items-center gap-2 text-[14px] font-semibold"><ShieldOff className="h-4 w-4 text-ink-muted" /> Blocking</h3>
          <p className="text-[13.5px] font-medium text-ink">Never blocked</p>
          <p className="mt-1 text-[12.5px] text-ink-muted">Private and reserved addresses are always on the never-block list, so the firewall feed can't cut off your own network.</p>
        </article>
      </div>
    </>
  );
}

export default function Verify({ me }: { me?: Me }) {
  usePage("Threat intel", "Verify");
  const [params, setParams] = useSearchParams();
  const [q, setQ] = useState(params.get("q") ?? "");
  const [tlp, setTlp] = useState("TLP:GREEN");
  const [providers, setProviders] = useState(params.get("providers") !== "false");
  const [query, setQuery] = useState<QueryInfo>();
  const [local, setLocal] = useState<Local>();
  const [cards, setCards] = useState<Record<string, ProviderCard | { pending: true; title: string }>>({});
  const [result, setResult] = useState<VerifyDone>();
  const [internal, setInternal] = useState<InternalResult>();
  const [error, setError] = useState<string>();
  const [running, setRunning] = useState(false);
  const abort = useRef<AbortController>();
  const analyst = me?.role === "admin" || me?.role === "analyst";

  const run = async (value: string) => {
    abort.current?.abort();
    const ac = new AbortController();
    abort.current = ac;
    setRunning(true);
    setError(undefined);
    setResult(undefined);
    setInternal(undefined);
    setQuery(undefined);
    setLocal(undefined);
    setCards({});
    try {
      const url = `/app/api/verify/stream?${new URLSearchParams({ q: value, tlp, providers: String(providers) })}`;
      const r = await fetch(url, { credentials: "same-origin", signal: ac.signal });
      await readEvents<VerifyEvent>(r, (ev) => {
        if (ev.event === "start") {
          setQuery(ev.query);
          setLocal({ known: ev.known, asset: ev.asset, allowlist: ev.allowlist, related: ev.related });
          setCards(Object.fromEntries(ev.pending.map((p) => [p.enricher, { pending: true as const, title: p.title }])));
        } else if (ev.event === "provider") {
          setCards((c) => ({ ...c, [ev.card.enricher]: ev.card }));
        } else if (ev.event === "done") {
          setResult(ev);
          setLocal({ known: ev.known, asset: ev.asset, allowlist: ev.allowlist, related: ev.related });
          setCards(Object.fromEntries(ev.cards.map((c) => [c.enricher, c])));
        } else if (ev.event === "internal") {
          setInternal(ev);
        } else {
          setError(ev.message);
        }
      });
    } catch (e) {
      if ((e as Error).name !== "AbortError") setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  useEffect(() => {
    const initial = params.get("q");
    if (initial) void run(initial);
    return () => abort.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (!q.trim()) return;
    setParams({ q: q.trim() }, { replace: true });
    void run(q.trim());
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Verify an indicator" sub="Our own intel first, then each provider as it answers. Paste a value defanged or not." />
        <form onSubmit={submit} className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <label className="relative flex-1">
            <span className="sr-only">Value</span>
            <Search className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input value={q} onChange={(e) => setQ(e.target.value)} className="ctl h-11 w-full pl-10 font-mono text-[14.5px]" placeholder="IP, domain, URL, hash or email" autoFocus spellCheck={false} maxLength={2000} />
          </label>
          <TlpSelect value={tlp} onChange={setTlp} />
          <label className="flex items-center gap-2 text-[13px] text-ink-muted" title="Off: only our intel and saved answers, nothing is sent out">
            <input type="checkbox" className="h-4 w-4 accent-accent" checked={providers} onChange={(e) => setProviders(e.target.checked)} /> Ask providers
          </label>
          <button className="btn-primary h-11 px-5" disabled={!q.trim() || running}>
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />} Verify
          </button>
        </form>
        <p className="mt-2 text-[12px] text-ink-faint">The marking decides which providers may see the value: TLP:CLEAR allows all, stricter markings keep it from public services.</p>
      </Card>

      {error && <p role="alert" className="rounded-card border border-down/30 bg-down/[0.06] px-4 py-3 text-[13.5px] text-down">{error}</p>}

      {internal && <InternalView r={internal} />}

      {query && (
        <Card>
          <div className="flex flex-wrap items-start justify-between gap-5">
            <div className="min-w-0 flex-1">
              <p className="mb-2 flex flex-wrap items-center gap-2 text-[12.5px] text-ink-muted">
                {query.typeLabel}
                {result ? <><VerdictPill verdict={result.verdict} label={result.verdictLabel} /><TlpTag tlp={result.tlp} /></> : <span className="inline-flex items-center gap-1.5 text-accent-soft"><Loader2 className="h-3.5 w-3.5 animate-spin" /> Checking</span>}
              </p>
              <h2 className="text-[22px] font-semibold"><Ioc value={query.value} /></h2>
              {result && <p className="mt-2 text-[12.5px] text-ink-faint">{result.summary}</p>}
            </div>
            {result && (
              <div className="max-w-md rounded-card border border-line bg-card-2/40 p-4">
                <div className="flex items-center gap-4">
                  <div className="text-center">
                    <p className={`text-[38px] font-bold leading-none tabular-nums ${result.verdict === "malicious" ? "text-down" : result.verdict === "suspicious" ? "text-warn" : "text-ink"}`}>{result.score}</p>
                    <p className="text-[11px] text-ink-faint">of 100</p>
                  </div>
                  <div>
                    <p className="label">Recommended</p>
                    <p className="text-[17px] font-semibold">{result.actionLabel}</p>
                    <p className="text-[12.5px] text-ink-muted"><Ioc value={result.actionText} mono={false} /></p>
                  </div>
                </div>
              </div>
            )}
          </div>
          {result && (
            <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-line pt-5">
              <CopyButton value={query.value} />
              {analyst && result.blockable && <BlockButton value={query.value} block={result.block} />}
              {analyst && <FlagButtons values={[query.value]} tlp={result.tlp} />}
              {analyst && <AddToCase values={[query.value]} />}
            </div>
          )}
        </Card>
      )}

      {local && (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <OurIntel local={local} />
          {Object.entries(cards).map(([name, c]) =>
            "pending" in c ? (
              <article key={name} className="rounded-card border border-line bg-card p-4" aria-busy="true">
                <h3 className="mb-3 text-[14px] font-semibold text-ink-muted">{c.title}</h3>
                <Skeleton className="mb-2 h-4 w-3/4" />
                <Skeleton className="h-3 w-1/2" />
              </article>
            ) : (
              <ProviderView key={name} c={c} />
            ),
          )}
          {result && (
            <article className="rounded-card border border-line bg-card p-4">
              <h3 className="mb-2 text-[14px] font-semibold">Second opinion</h3>
              {result.links.length ? (
                <>
                  <p className="mb-3 text-[12.5px] text-ink-muted">Opens the public site in a new tab; the value is sent there.</p>
                  <div className="flex flex-wrap gap-2">
                    {result.links.map((l) => (
                      <a key={l.title} href={l.url} target="_blank" rel="noopener noreferrer" className="btn-ghost h-8 text-[12.5px]">
                        {l.title} <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    ))}
                  </div>
                </>
              ) : (
                <p className="text-[12.5px] text-ink-muted">None offered: this value's marking doesn't allow sending it to public sites.</p>
              )}
            </article>
          )}
        </div>
      )}
    </div>
  );
}
