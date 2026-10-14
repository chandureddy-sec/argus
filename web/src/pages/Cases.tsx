import { Briefcase, Loader2, Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { TlpTag } from "../components/intel";
import { SevPill } from "../components/recon";
import { Empty, Failed, Skeleton } from "../components/states";
import { Card, CardHead, Segmented } from "../components/ui";
import { send, useV1, type CaseDetail, type CaseRow, type Me } from "../lib/api";
import { ago } from "../lib/format";
import { TLPS } from "../lib/ioc";
import { usePage } from "../lib/page";

const SHOW = ["Open", "Closed", "All"] as const;

export default function Cases({ me }: { me?: Me }) {
  usePage("Response", "Cases");
  const [show, setShow] = useState<(typeof SHOW)[number]>("Open");
  const list = useV1<CaseRow[]>("cases", { status: show === "All" ? undefined : show.toLowerCase() });
  const nav = useNavigate();
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("medium");
  const [tlp, setTlp] = useState("TLP:AMBER");
  const [summary, setSummary] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const analyst = me?.role === "admin" || me?.role === "analyst";

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const c = await send<CaseDetail>("POST", "/api/v1/cases", { title, severity, tlp, summary });
      nav(`/cases/${c.id}`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <div className="grid gap-6 xl:grid-cols-[minmax(0,8fr)_minmax(0,4fr)]">
        <Card className="!p-0">
          <div className="p-5 pb-3 sm:p-6 sm:pb-3">
            <CardHead title="Cases" sub="Investigations: the indicators, vulnerabilities and notes behind one incident, with a report to share">
              <Segmented value={show} options={SHOW} onChange={setShow} label="Which cases" />
            </CardHead>
          </div>
          {list.error && !list.data ? (
            <Failed error={list.error} onRetry={list.reload} />
          ) : !list.data ? (
            <Skeleton className="mx-6 mb-6 h-32" />
          ) : !list.data.length ? (
            <Empty>No {show === "All" ? "" : show.toLowerCase()} cases.</Empty>
          ) : (
            <ul className="divide-y divide-line/70 border-t border-line">
              {list.data.map((c) => (
                <li key={c.id}>
                  <Link to={`/cases/${c.id}`} className="group flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-4 hover:bg-accent/[0.05] sm:px-6">
                    <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-accent/10 text-accent-soft ring-1 ring-accent/20">
                      <Briefcase className="h-4 w-4" />
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-medium group-hover:text-accent-soft">
                        <span className="text-ink-faint">#{c.id}</span> {c.title}
                      </span>
                      <span className="block text-[12.5px] text-ink-faint">
                        {c.items} item{c.items === 1 ? "" : "s"} · opened by {c.created_by} {ago(c.created_at)} · updated {ago(c.updated_at)}
                      </span>
                    </span>
                    <SevPill sev={c.severity} />
                    <TlpTag tlp={c.tlp} />
                    <span className={`text-[12.5px] ${c.status === "open" ? "text-up" : "text-ink-faint"}`}>{c.status}</span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>

        <Card>
          <CardHead title="Open a case" sub={analyst ? "Add evidence from any indicator, Verify or Bulk check afterwards." : "Opening cases needs the analyst role."} />
          <form onSubmit={create} className="space-y-3">
            <fieldset disabled={!analyst || busy} className="space-y-3">
              <input value={title} onChange={(e) => setTitle(e.target.value)} className="ctl w-full" placeholder="e.g. Beaconing from build server" maxLength={200} required />
              <div className="grid grid-cols-2 gap-3">
                <label>
                  <span className="label mb-1 block">Severity</span>
                  <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="ctl w-full">
                    {["low", "medium", "high", "critical"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label>
                  <span className="label mb-1 block">Marking</span>
                  <select value={tlp} onChange={(e) => setTlp(e.target.value)} className="ctl w-full">
                    {TLPS.map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                </label>
              </div>
              <textarea value={summary} onChange={(e) => setSummary(e.target.value)} rows={4} className="ctl h-auto w-full py-2" placeholder="What happened, how it was found" maxLength={20000} />
            </fieldset>
            <button className="btn-primary w-full" disabled={!analyst || !title.trim() || busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Open case
            </button>
            {error && <p className="text-[12.5px] text-down">{error}</p>}
          </form>
        </Card>
      </div>
    </div>
  );
}
