import { Loader2, Save } from "lucide-react";
import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Skeleton } from "../components/states";
import { Card, CardHead } from "../components/ui";
import { get, send, type Me, type SourceOut } from "../lib/api";
import { TLPS } from "../lib/ioc";
import { usePage } from "../lib/page";

interface Form {
  title: string;
  url: string;
  format: string;
  ioc_type: string;
  verdict: string;
  confidence: number;
  interval_minutes: number;
  tlp: string;
  reliability: string;
  comment_char: string;
  value_column: number;
  json_path: string;
  auth_header: string;
  secret: string;
  clear_secret: boolean;
  upstream: string;
}

const EMPTY: Form = {
  title: "", url: "", format: "text", ioc_type: "auto", verdict: "malicious", confidence: 70, interval_minutes: 360,
  tlp: "TLP:CLEAR", reliability: "C", comment_char: "#", value_column: 0, json_path: "", auth_header: "", secret: "",
  clear_secret: false, upstream: "",
};
const GRADES: [string, string][] = [["A", "A · completely reliable"], ["B", "B · usually reliable"], ["C", "C · fairly reliable"], ["D", "D · not usually reliable"], ["E", "E · unreliable"], ["F", "F · can't be judged"]];

function Field({ label, hint, children, wide }: { label: string; hint?: string; children: ReactNode; wide?: boolean }) {
  return (
    <label className={`block ${wide ? "sm:col-span-2" : ""}`}>
      <span className="label mb-1.5 block">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-[12px] text-ink-faint">{hint}</span>}
    </label>
  );
}

export default function FeedForm({ me }: { me?: Me }) {
  const { name } = useParams();
  usePage("Platform", "Feed catalog", name ? "Edit feed" : "Add a source");
  const nav = useNavigate();
  const [f, setF] = useState<Form>(EMPTY);
  const [hasSecret, setHasSecret] = useState(false);
  const [loaded, setLoaded] = useState(!name);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const set = <K extends keyof Form>(k: K, v: Form[K]) => setF((x) => ({ ...x, [k]: v }));

  useEffect(() => {
    if (!name) return;
    get<Form & { has_secret: boolean }>(`feeds/${name}/form`)
      .then((d) => {
        setF({ ...EMPTY, ...d, secret: "", clear_secret: false });
        setHasSecret(d.has_secret);
        setLoaded(true);
      })
      .catch((e: Error) => setError(e.message));
  }, [name]);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const body = { ...f, confidence: Number(f.confidence), interval_minutes: Number(f.interval_minutes), value_column: Number(f.value_column) };
      const s = name
        ? await send<SourceOut>("PUT", `/api/v1/sources/custom/${name}`, body)
        : await send<SourceOut>("POST", "/api/v1/sources/custom", body);
      nav(`/feeds/${s.name}`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  if (me && me.role !== "admin") {
    return (
      <div className="mx-auto max-w-[880px] px-4 py-8 sm:px-6">
        <Card>
          <p className="text-ink-muted">Adding and editing feeds needs the admin role.</p>
        </Card>
      </div>
    );
  }

  return (
    <div className="mx-auto w-full max-w-[880px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <Card>
        <CardHead title={name ? `Edit ${f.title || name}` : "Add a source"} sub="Point Argus at a public or private list of known-bad indicators. It pulls the list on your schedule and matches it locally: nothing is sent anywhere when an indicator is checked." />
        {!loaded ? (
          <Skeleton className="h-96" />
        ) : (
          <form onSubmit={submit} className="space-y-7" autoComplete="off">
            <fieldset className="grid gap-4 sm:grid-cols-2">
              <legend className="mb-3 text-[14px] font-semibold">The feed</legend>
              <Field label="Name" wide>
                <input value={f.title} onChange={(e) => set("title", e.target.value)} className="ctl w-full" placeholder="e.g. Partner SOC bad IPs" minLength={3} maxLength={80} required />
              </Field>
              <Field label="Feed URL" wide>
                <input value={f.url} onChange={(e) => set("url", e.target.value)} className="ctl w-full font-mono" type="url" placeholder="https://example.org/blocklist.txt" required spellCheck={false} />
              </Field>
              <Field label="Format">
                <select value={f.format} onChange={(e) => set("format", e.target.value)} className="ctl w-full">
                  <option value="text">Plain text, one per line</option>
                  <option value="csv">CSV</option>
                  <option value="json">JSON</option>
                </select>
              </Field>
              <Field label="Indicator type">
                <select value={f.ioc_type} onChange={(e) => set("ioc_type", e.target.value)} className="ctl w-full">
                  <option value="auto">Detect each value</option>
                  <option value="ip">IP addresses / ranges</option>
                  <option value="domain">Domains</option>
                  <option value="url">URLs</option>
                  <option value="hash">File hashes</option>
                </select>
              </Field>
              <Field label="Comment marker" hint="Lines starting with it are skipped">
                <input value={f.comment_char} onChange={(e) => set("comment_char", e.target.value)} className="ctl w-full font-mono" maxLength={4} />
              </Field>
              {f.format === "csv" && (
                <Field label="Value column" hint="CSV only; the first column is 0">
                  <input value={f.value_column} onChange={(e) => set("value_column", Number(e.target.value))} type="number" min={0} max={255} className="ctl w-full" />
                </Field>
              )}
              {f.format === "json" && (
                <Field label="JSON field" hint="e.g. data.ip_address; empty for a list of strings">
                  <input value={f.json_path} onChange={(e) => set("json_path", e.target.value)} className="ctl w-full font-mono" maxLength={200} spellCheck={false} />
                </Field>
              )}
            </fieldset>

            <fieldset className="grid gap-4 border-t border-line pt-6 sm:grid-cols-2">
              <legend className="mb-3 text-[14px] font-semibold">How much to trust it</legend>
              <Field label="Verdict">
                <select value={f.verdict} onChange={(e) => set("verdict", e.target.value)} className="ctl w-full">
                  <option value="malicious">Malicious</option>
                  <option value="suspicious">Suspicious (context, never blocks on its own)</option>
                </select>
              </Field>
              <Field label="Confidence (0–100)">
                <input value={f.confidence} onChange={(e) => set("confidence", Number(e.target.value))} type="number" min={0} max={100} className="ctl w-full" required />
              </Field>
              <Field label="Reliability">
                <select value={f.reliability} onChange={(e) => set("reliability", e.target.value)} className="ctl w-full">
                  {GRADES.map(([v, l]) => (
                    <option key={v} value={v}>
                      {l}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Marking (TLP)">
                <select value={f.tlp} onChange={(e) => set("tlp", e.target.value)} className="ctl w-full">
                  {TLPS.map((t) => (
                    <option key={t}>{t}</option>
                  ))}
                </select>
              </Field>
              <Field label="Pull every (minutes)" hint="15 minutes to 7 days">
                <input value={f.interval_minutes} onChange={(e) => set("interval_minutes", Number(e.target.value))} type="number" min={15} max={10080} className="ctl w-full" required />
              </Field>
              <Field label="Original producer" hint="If it re-publishes someone else's list (corroboration counts it once)">
                <input value={f.upstream} onChange={(e) => set("upstream", e.target.value)} className="ctl w-full" placeholder="e.g. abuse.ch" maxLength={60} />
              </Field>
              <p className="text-[12.5px] text-ink-muted sm:col-span-2">
                Score = confidence × reliability while the feed lists a value: confidence {f.confidence} from grade {f.reliability} scores about{" "}
                <b className="text-ink">{Math.round(Number(f.confidence) * ({ A: 1, B: 0.85, C: 0.7, D: 0.5, E: 0.3, F: 0.2 }[f.reliability] ?? 0.7))}</b>. 60 or more reads as malicious, 30 or more as suspicious.
              </p>
            </fieldset>

            <fieldset className="grid gap-4 border-t border-line pt-6 sm:grid-cols-2">
              <legend className="mb-3 text-[14px] font-semibold">Credentials (optional)</legend>
              <Field label="Auth header">
                <input value={f.auth_header} onChange={(e) => set("auth_header", e.target.value)} className="ctl w-full font-mono" placeholder="Authorization or x-api-key" maxLength={64} spellCheck={false} />
              </Field>
              <Field label="API key / token" hint="Stored encrypted; never shown again">
                <input value={f.secret} onChange={(e) => set("secret", e.target.value)} type="password" autoComplete="new-password" className="ctl w-full" placeholder={hasSecret ? "Leave empty to keep the stored key" : "Sent in the header above"} maxLength={4000} />
              </Field>
              {hasSecret && (
                <label className="flex items-center gap-2 text-[13px] text-ink-muted sm:col-span-2">
                  <input type="checkbox" className="h-4 w-4 accent-[#F43F5E]" checked={f.clear_secret} onChange={(e) => set("clear_secret", e.target.checked)} /> Remove the stored key
                </label>
              )}
            </fieldset>

            {error && <p role="alert" className="rounded-ctl border border-down/30 bg-down/[0.07] px-3 py-2 text-[13.5px] text-down">{error}</p>}
            <div className="flex items-center justify-between gap-3 border-t border-line pt-5">
              <p className="text-[12px] text-ink-faint">Fetched like every feed: http(s) only, never a private address, at most 20 MB, at most every 5 minutes.</p>
              <button className="btn-primary h-10 px-5" disabled={busy}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} {name ? "Save changes" : "Add feed"}
              </button>
            </div>
          </form>
        )}
      </Card>
    </div>
  );
}
