import { Download, FileUp, Loader2, Play, ShieldCheck, Wand2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { TlpTag } from "../components/intel";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { send, useV1, type Me } from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

interface GenRule {
  kind: "sigma" | "suricata" | "yara" | "wazuh";
  name: string;
  title: string;
  body: string;
  tlp: string;
  confidence: number;
  count: number;
  tags: string[];
  queries: Record<string, string>;
  problems: string[];
}

interface Hunt {
  technique: string;
  title: string;
  description: string;
  dataSources: string[];
  falsepositives: string[];
  level: string;
  sigma: string;
  queries: Record<string, string>;
}

interface Coverage {
  rules: number;
  relevant: number;
  covered: number;
  gaps: { technique: string; name: string; weight: number; why: string[] }[];
  items: { technique: string; name: string; weight: number; why: string[]; rules: number; covered: boolean; hunt: boolean }[];
  gapLayer: unknown;
  coverageLayer: unknown;
}

interface Pack {
  id: number;
  createdAt: string;
  title: string;
  tlp: string;
  indicators: number;
  lookbackDays: number;
  from: string;
  queries: Record<string, { rule: string; query: string }[]>;
}

const TABS = ["Rules from intel", "Hunts", "Coverage", "Retro-hunts"] as const;
type Tab = (typeof TABS)[number];
const BACKEND: Record<string, string> = { splunk: "Splunk SPL", kql: "Sentinel / Defender KQL", lucene: "Elastic Lucene", sigma: "Sigma" };

function Code({ text }: { text: string }) {
  return <pre className="max-h-72 overflow-auto rounded-ctl border border-line bg-bg p-3 font-mono text-[12px] leading-relaxed text-ink-muted">{text}</pre>;
}

function download(name: string, text: string, type = "application/json") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function Generate({ canRun }: { canRun: boolean }) {
  const [minScore, setMinScore] = useState(60);
  const [maxTlp, setMaxTlp] = useState("TLP:GREEN");
  const [formats, setFormats] = useState<string[]>(["sigma", "suricata", "yara", "wazuh"]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [rules, setRules] = useState<GenRule[]>();
  const [open, setOpen] = useState<string>();
  const [backend, setBackend] = useState("sigma");
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const r = await send<{ rules: GenRule[] }>("POST", "/api/v1/detections/generate", { min_score: minScore, max_tlp: maxTlp, formats });
      setRules(r.rules);
      setOpen(r.rules[0]?.name);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const zip = `/api/v1/detections/pack.zip?min_score=${minScore}&max_tlp=${encodeURIComponent(maxTlp)}&formats=${formats.join(",")}`;
  if (!canRun) return <Empty>Analysts and admins can generate rules.</Empty>;
  return (
    <div className="space-y-4">
      <form onSubmit={run} className="flex flex-wrap items-end gap-3 text-[13px]">
        <label>
          <span className="mb-1 block text-ink-muted">Indicators scoring at least</span>
          <input type="number" min={0} max={100} className="ctl h-9 w-24" value={minScore} onChange={(e) => setMinScore(Number(e.target.value))} />
        </label>
        <label>
          <span className="mb-1 block text-ink-muted">Up to marking</span>
          <select className="ctl h-9" value={maxTlp} onChange={(e) => setMaxTlp(e.target.value)}>
            {["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"].map((t) => (
              <option key={t}>{t}</option>
            ))}
          </select>
        </label>
        <fieldset className="flex flex-wrap gap-3 pb-2">
          {["sigma", "suricata", "yara", "wazuh"].map((f) => (
            <label key={f} className="flex items-center gap-1.5">
              <input type="checkbox" className="h-4 w-4 accent-accent" checked={formats.includes(f)} onChange={(e) => setFormats(e.target.checked ? [...formats, f] : formats.filter((x) => x !== f))} />
              {f}
            </label>
          ))}
        </fieldset>
        <button className="btn-primary h-9" disabled={busy || !formats.length}>
          {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Wand2 className="h-4 w-4" />} Generate
        </button>
        <a className="btn-ghost h-9" href={zip}>
          <Download className="h-4 w-4" /> Zip pack
        </a>
      </form>
      <p className="text-[12.5px] text-ink-faint">
        Every rule passes its syntax check (pySigma, suricataparser, yara, XML) and carries author, date, references, ATT&CK tags, TLP, confidence and false-positive notes. Only indicators within your clearance are used. Review before enabling.
      </p>
      {error && <p className="text-[13px] text-down">{error}</p>}
      {rules && !rules.length && <Empty>No indicators at that score and marking.</Empty>}
      {rules && rules.length > 0 && (
        <ul className="divide-y divide-line rounded-ctl border border-line">
          {rules.map((r) => (
            <li key={`${r.kind}-${r.name}`} className="px-4 py-2.5">
              <button className="flex w-full flex-wrap items-center gap-2 text-left text-[13px]" onClick={() => setOpen(open === r.name ? undefined : r.name)}>
                <span className="w-16 rounded bg-chip px-1.5 text-center text-[11.5px] font-semibold uppercase text-chip-ink ring-1 ring-line">{r.kind}</span>
                <span className="min-w-0 flex-1 font-medium">{r.title}</span>
                <TlpTag tlp={r.tlp} />
                <span className="text-ink-faint">{r.count} indicator{r.count === 1 ? "" : "s"} · confidence {r.confidence}</span>
                {r.problems.length > 0 && <span className="text-warn">{r.problems.length} validator note(s)</span>}
              </button>
              {open === r.name && (
                <div className="mt-3 space-y-2">
                  {r.kind === "sigma" && (
                    <Segmented value={backend} options={["sigma", "splunk", "kql", "lucene"] as const} onChange={setBackend} label="Format" />
                  )}
                  <Code text={r.kind === "sigma" && backend !== "sigma" ? r.queries[backend] : r.body} />
                  <button className="btn-ghost h-8 text-[12.5px]" onClick={() => download(r.name, r.body, "text/plain")}>
                    <Download className="h-3.5 w-3.5" /> {r.name}
                  </button>
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Hunts() {
  const [params, setParams] = useSearchParams();
  const technique = params.get("technique") ?? "";
  const { data, error, reload } = useV1<Hunt[]>("detections/hunts", technique ? { technique } : {});
  const [backend, setBackend] = useState<string>("splunk");
  if (error && !data) return <Failed error={error} onRetry={reload} />;
  if (!data) return <Skeleton className="h-40" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented value={backend} options={["splunk", "kql", "lucene", "sigma"] as const} onChange={setBackend} label="Query language" />
        {technique && (
          <button className="btn-ghost h-8 text-[12.5px]" onClick={() => setParams({ tab: "Hunts" })}>
            Showing {technique} · show all
          </button>
        )}
      </div>
      {!data.length ? (
        <Empty>No hunt for {technique} in the library yet.</Empty>
      ) : (
        <ul className="space-y-4">
          {data.map((h) => (
            <li key={h.technique} className="rounded-ctl border border-line p-4">
              <p className="flex flex-wrap items-center gap-2 text-[13.5px]">
                <Link to={`/entities/${h.technique}`} className="font-mono text-accent-soft hover:underline">{h.technique}</Link>
                <b>{h.title.replace(/^Hunt: /, "")}</b>
                <span className="text-[12px] text-ink-faint">level {h.level}</span>
              </p>
              <p className="mt-1 text-[13px] text-ink-muted">{h.description}</p>
              <p className="mt-1 text-[12.5px]"><span className="text-ink-faint">Needs:</span> {h.dataSources.join("; ")}</p>
              <p className="text-[12.5px]"><span className="text-ink-faint">False positives:</span> {h.falsepositives.join("; ")}</p>
              <div className="mt-2">
                <p className="label mb-1">{BACKEND[backend]}</p>
                <Code text={backend === "sigma" ? h.sigma : h.queries[backend]} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function CoverageTab({ canImport }: { canImport: boolean }) {
  const { data, error, reload } = useV1<Coverage>("detections/coverage");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>();
  const upload = async (files: FileList | null) => {
    if (!files?.length) return;
    setBusy(true);
    setMsg(undefined);
    try {
      const fd = new FormData();
      for (const f of Array.from(files)) fd.append("files", f);
      const r = await fetch("/api/v1/detections/inventory", { method: "POST", body: fd, credentials: "same-origin" });
      const body = await r.json();
      if (!r.ok) throw new Error(typeof body.detail === "string" ? body.detail : `${r.status}`);
      setMsg(`${body.added} added, ${body.updated} updated${body.errors?.length ? ` · ${body.errors.length} file(s) skipped: ${body.errors.slice(0, 2).join("; ")}` : ""}`);
      reload();
    } catch (e) {
      setMsg((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (error && !data) return <Failed error={error} onRetry={reload} />;
  if (!data) return <Skeleton className="h-40" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 text-[13px]">
        <span>
          <b>{data.covered}</b> of <b>{data.relevant}</b> relevant techniques covered by <b>{data.rules}</b> rule{data.rules === 1 ? "" : "s"} in the inventory.
        </span>
        {canImport && (
          <label className="btn-ghost h-9 cursor-pointer">
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileUp className="h-4 w-4" />} Import Sigma rules (.yml or .zip)
            <input type="file" multiple accept=".yml,.yaml,.zip" className="hidden" onChange={(e) => upload(e.target.files)} />
          </label>
        )}
        <button className="btn-ghost h-9" onClick={() => download("argus_gaps_layer.json", JSON.stringify(data.gapLayer, null, 1))}>
          <Download className="h-4 w-4" /> Gap layer
        </button>
        <button className="btn-ghost h-9" onClick={() => download("argus_coverage_layer.json", JSON.stringify(data.coverageLayer, null, 1))}>
          <Download className="h-4 w-4" /> Coverage layer
        </button>
      </div>
      {msg && <p className="text-[13px] text-ink-muted">{msg}</p>}
      <p className="text-[12.5px] text-ink-faint">
        Relevant = watched by a PIR (weight 5) or used by malware and actors your current indicators point at (1 per family). A rule covers a technique when it carries its attack.tNNNN tag (a sub-technique rule covers its parent). Load the layers in the MITRE ATT&CK Navigator.
      </p>
      {!data.items.length ? (
        <Empty>No relevant techniques yet: add PIRs with techniques, or load ATT&CK and collect feeds that name malware.</Empty>
      ) : (
        <table className="w-full text-[13px]">
          <thead>
            <tr className="border-b border-line text-left text-[12px] uppercase tracking-wide text-ink-muted">
              <th className="py-2">Technique</th>
              <th className="py-2">Why it matters</th>
              <th className="py-2 text-right">Relevance</th>
              <th className="py-2 text-right">Rules</th>
              <th className="py-2 text-right">Hunt</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map((i) => (
              <tr key={i.technique} className="border-b border-line/60">
                <td className="py-2">
                  <Link to={`/entities/${i.technique}`} className="font-mono hover:text-accent-soft">{i.technique}</Link> {i.name}
                </td>
                <td className="py-2 text-ink-muted">{i.why.join("; ")}</td>
                <td className="py-2 text-right tabular-nums">{i.weight}</td>
                <td className={`py-2 text-right tabular-nums ${i.covered ? "text-up" : "text-down"}`}>{i.covered ? i.rules : "gap"}</td>
                <td className="py-2 text-right">
                  {i.hunt ? <Link to={`/detections?tab=Hunts&technique=${i.technique}`} className="text-[12.5px] text-accent-soft hover:underline">queries</Link> : <span className="text-[12px] text-ink-faint">—</span>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function Retro({ canRun }: { canRun: boolean }) {
  const { data, error, reload } = useV1<Pack[]>("detections/retro");
  const [backend, setBackend] = useState("splunk");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>();
  if (error && !data) return <Failed error={error} onRetry={reload} />;
  if (!data) return <Skeleton className="h-40" />;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Segmented value={backend} options={["splunk", "kql", "lucene", "sigma"] as const} onChange={setBackend} label="Query language" />
        {canRun && (
          <button
            className="btn-ghost h-9"
            disabled={busy}
            onClick={async () => {
              setBusy(true);
              try {
                const r = await send<{ created: number | null }>("POST", "/api/v1/detections/retro/run");
                setMsg(r.created ? "New pack created" : "Nothing new at 80+ since the last pack");
                reload();
              } catch (e) {
                setMsg((e as Error).message);
              } finally {
                setBusy(false);
              }
            }}
          >
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Check now
          </button>
        )}
        {msg && <span className="text-[13px] text-ink-muted">{msg}</span>}
      </div>
      <p className="text-[12.5px] text-ink-faint">Every 15 minutes, indicators that newly reach 80+ get a query pack: run it over the last 30 days of logs, because today's indicator may have been active last week.</p>
      {!data.length ? (
        <Empty>No packs yet.</Empty>
      ) : (
        <ul className="space-y-3">
          {data.map((p) => (
            <li key={p.id} className="rounded-ctl border border-line p-4">
              <p className="flex flex-wrap items-center gap-2 text-[13px]">
                <ShieldCheck className="h-4 w-4 text-accent-soft" /> <b>{p.title}</b> <TlpTag tlp={p.tlp} />
                <span className="text-ink-faint">{ago(p.createdAt)} · search the last {p.lookbackDays} days</span>
              </p>
              {(p.queries[backend] ?? []).map((q, i) => (
                <div key={i} className="mt-2">
                  <p className="text-[12px] text-ink-faint">{q.rule}</p>
                  <Code text={q.query} />
                </div>
              ))}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export default function Detections({ me }: { me?: Me }) {
  usePage("Threat intel", "Detections");
  const [params, setParams] = useSearchParams();
  const tab = (TABS as readonly string[]).includes(params.get("tab") ?? "") ? (params.get("tab") as Tab) : "Rules from intel";
  const analyst = me?.role === "admin" || me?.role === "analyst";
  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title="Detection engineering" sub="Rules from your intelligence, hunts per ATT&CK technique, coverage gaps, and retro-hunts for new indicators">
          <Segmented value={tab} options={TABS} onChange={(t) => setParams({ tab: t })} label="Section" />
        </CardHead>
        {tab === "Rules from intel" && <Generate canRun={analyst} />}
        {tab === "Hunts" && <Hunts />}
        {tab === "Coverage" && <CoverageTab canImport={analyst} />}
        {tab === "Retro-hunts" && <Retro canRun={analyst} />}
      </Card>
    </div>
  );
}
