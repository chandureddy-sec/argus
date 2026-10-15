import { Briefcase, Loader2, ShieldBan, ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";
import { Link } from "react-router-dom";
import { post, send, useV1, type Block, type CaseRow } from "../lib/api";

/** Put a value on the blocklist (monitor mode; enforcing is a separate, approved step). */
export function BlockButton({ value, block, onDone }: { value: string; block?: Block | { id: number; mode: string; state: string } | null; onDone?: (b: Block) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [made, setMade] = useState<Block>();
  const current = made ?? block;
  if (current && current.state !== "lifted" && current.state !== "expired") {
    return (
      <Link to="/blocklist" className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[12.5px] font-medium ring-1 ${current.mode === "enforce" ? "bg-down/10 text-down ring-down/25" : "bg-info/10 text-info-soft ring-info/20"}`}>
        <ShieldBan className="h-3.5 w-3.5" /> {current.mode === "enforce" ? "Blocked on firewalls" : "Blocked (monitor)"}
      </Link>
    );
  }
  return (
    <span className="inline-flex items-center gap-2">
      <button
        className="btn-ghost h-9"
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          setError(undefined);
          try {
            const b = await send<Block>("POST", "/api/v1/blocks", { value, note: "from Argus" });
            setMade(b);
            onDone?.(b);
          } catch (e) {
            setError((e as Error).message);
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldBan className="h-4 w-4" />} Block
      </button>
      {error && <span className="max-w-xs text-[12.5px] text-down">{error}</span>}
    </span>
  );
}

/** Flag malicious / not malicious: analyst feedback that moves the score and the sources' weights. */
export function FlagButtons({ values, tlp = "TLP:GREEN", onDone }: { values: string[]; tlp?: string; onDone?: () => void }) {
  const [busy, setBusy] = useState<string>();
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>();
  const go = async (verdict: "tp" | "fp") => {
    setBusy(verdict);
    setMsg(undefined);
    try {
      const r = await post<{ done: unknown[]; refused: { value: string; why: string }[] }>("verify/flag", { values, verdict, tlp });
      setMsg(r.refused.length ? { ok: false, text: r.refused[0].why } : { ok: true, text: verdict === "tp" ? "Flagged malicious" : "Marked not malicious" });
      onDone?.();
    } catch (e) {
      setMsg({ ok: false, text: (e as Error).message });
    } finally {
      setBusy(undefined);
    }
  };
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <button className="btn-ghost h-9 hover:!border-down/50 hover:!text-down" disabled={!!busy} onClick={() => go("tp")}>
        {busy === "tp" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldX className="h-4 w-4" />} Flag malicious
      </button>
      <button className="btn-ghost h-9 hover:!border-up/50 hover:!text-up" disabled={!!busy} onClick={() => go("fp")}>
        {busy === "fp" ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Not malicious
      </button>
      {msg && <span className={`text-[12.5px] ${msg.ok ? "text-up" : "text-down"}`}>{msg.text}</span>}
    </span>
  );
}

/** Add evidence to an open case: an indicator by id, or values to look up. */
export function AddToCase({ indicatorId, values, cve }: { indicatorId?: number; values?: string[]; cve?: string }) {
  const cases = useV1<CaseRow[]>("cases", { status: "open" });
  const [pick, setPick] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string; id?: number }>();
  if (!cases.data?.length) {
    return (
      <Link to="/cases" className="btn-ghost h-9">
        <Briefcase className="h-4 w-4" /> New case
      </Link>
    );
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <select className="ctl h-9 max-w-[200px] text-[13px]" value={pick} onChange={(e) => setPick(e.target.value)} aria-label="Case">
        <option value="">Add to case…</option>
        {cases.data.map((c) => (
          <option key={c.id} value={c.id}>
            #{c.id} {c.title.slice(0, 40)}
          </option>
        ))}
      </select>
      <button
        className="btn-ghost h-9"
        disabled={!pick || busy}
        onClick={async () => {
          setBusy(true);
          setMsg(undefined);
          try {
            const body = indicatorId
              ? { kind: "indicator", ref: String(indicatorId) }
              : cve
                ? { kind: "vulnerability", ref: cve }
                : { values: values ?? [] };
            await send("POST", `/api/v1/cases/${pick}/items`, body);
            setMsg({ ok: true, text: "Added", id: Number(pick) });
          } catch (e) {
            setMsg({ ok: false, text: (e as Error).message });
          } finally {
            setBusy(false);
          }
        }}
      >
        {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Briefcase className="h-4 w-4" />} Add
      </button>
      {msg && (msg.ok ? <Link to={`/cases/${msg.id}`} className="text-[12.5px] text-up hover:underline">Added · open case</Link> : <span className="text-[12.5px] text-down">{msg.text}</span>)}
    </span>
  );
}
