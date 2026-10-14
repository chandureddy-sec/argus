import { Info, Loader2, Radar, ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { EngineBanner } from "../components/recon";
import { Card, CardHead, Segmented } from "../components/ui";
import { post, type Me } from "../lib/api";
import { usePage } from "../lib/page";

const MODES = ["Passive", "Active", "Both"] as const;
type Mode = (typeof MODES)[number];
const DOMAIN = /^(?=.{3,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

const ABOUT: Record<Mode, string> = {
  Passive:
    "Only public sources: certificate logs, DNS, RDAP, internet scan databases and more. Nothing is sent to the target, so it is safe for any domain.",
  Active:
    "Contacts the target directly: HTTP probing, TLS and headers, optional port and nmap scans. Only for systems you are authorised to test.",
  Both: "Passive discovery first, then active checks on what it finds. Only for systems you are authorised to test.",
};

function Toggle({ checked, onChange, label, hint, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; hint: string; disabled?: boolean }) {
  return (
    <label className={`flex items-start gap-3 rounded-ctl border border-line bg-card-2/40 p-3.5 ${disabled ? "opacity-50" : "cursor-pointer hover:border-accent/40"}`}>
      <input type="checkbox" className="mt-0.5 h-4 w-4 accent-[#1F6BFF]" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span>
        <span className="block text-[14px] font-medium text-ink">{label}</span>
        <span className="block text-[12.5px] text-ink-muted">{hint}</span>
      </span>
    </label>
  );
}

export default function NewScan({ me }: { me?: Me }) {
  usePage("Attack surface", "New scan");
  const nav = useNavigate();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<Mode>("Passive");
  const [authorized, setAuthorized] = useState(false);
  const [ports, setPorts] = useState(false);
  const [nmap, setNmap] = useState(false);
  const [profile, setProfile] = useState("quick");
  const [nmapPorts, setNmapPorts] = useState("");
  const [archive, setArchive] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const active = mode !== "Passive";
  const admin = me?.role === "admin";
  const viewer = me?.role === "viewer";
  const clean = target.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const validTarget = DOMAIN.test(clean);
  const canSubmit = validTarget && !busy && !viewer && (!active || (admin && authorized));

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(undefined);
    try {
      const res = await post<{ job_id: string }>("recon/scans", {
        target: clean,
        mode: mode.toLowerCase(),
        authorized: active && authorized,
        ports: active && ports,
        nmap: active && nmap,
        nmap_profile: profile,
        nmap_ports: nmapPorts.trim(),
        archive_raw: archive,
      });
      nav(`/scans/job/${res.job_id}`);
    } catch (err) {
      setError((err as Error).message);
      setBusy(false);
    }
  };

  return (
    <div className="mx-auto w-full max-w-[880px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      <EngineBanner />
      <Card>
        <CardHead title="New scan" sub="Map a domain's attack surface with the ReconX engine" />
        <form onSubmit={submit} className="space-y-6">
          <label className="block">
            <span className="label mb-1.5 block">Target domain</span>
            <input
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="ctl h-11 w-full font-mono text-[15px]"
              placeholder="example.com"
              autoFocus
              spellCheck={false}
              autoComplete="off"
              aria-invalid={target !== "" && !validTarget}
            />
            {target !== "" && !validTarget && <span className="mt-1.5 block text-[12.5px] text-down">Enter a domain such as example.com (no IPs or paths).</span>}
          </label>

          <div>
            <span className="label mb-1.5 block">Mode</span>
            <Segmented value={mode} options={MODES} onChange={setMode} label="Scan mode" />
            <p className="mt-2.5 flex gap-2 text-[13px] text-ink-muted">
              <Info className="mt-0.5 h-4 w-4 shrink-0 text-accent-soft" />
              {ABOUT[mode]}
            </p>
          </div>

          {active && (
            <div className="space-y-3 rounded-card border border-warn/30 bg-warn/[0.05] p-4">
              {!admin && (
                <p className="flex gap-2 text-[13px] text-warn">
                  <ShieldAlert className="h-4 w-4 shrink-0" /> Active scans need the admin role.
                </p>
              )}
              <label className="flex cursor-pointer items-start gap-3">
                <input type="checkbox" className="mt-0.5 h-4 w-4 accent-[#F59E0B]" checked={authorized} disabled={!admin} onChange={(e) => setAuthorized(e.target.checked)} />
                <span className="text-[13.5px] text-ink">
                  I am authorised to actively test <b className="font-mono">{clean || "this domain"}</b> and the systems it resolves to.
                  <span className="block text-[12.5px] text-ink-muted">Recorded in the audit log with your name.</span>
                </span>
              </label>
              <div className="grid gap-3 sm:grid-cols-2">
                <Toggle checked={ports} onChange={setPorts} disabled={!admin} label="Port scan" hint="Common ports on live hosts" />
                <Toggle checked={nmap} onChange={setNmap} disabled={!admin} label="nmap service scan" hint="Versions and default scripts (-sV -sC)" />
              </div>
              {nmap && (
                <div className="grid gap-3 sm:grid-cols-2">
                  <label>
                    <span className="label mb-1.5 block">nmap profile</span>
                    <select value={profile} onChange={(e) => setProfile(e.target.value)} className="ctl w-full">
                      <option value="quick">Quick · top ports, ~10 min max</option>
                      <option value="aggressive">Aggressive · OS and scripts, ~25 min</option>
                      <option value="full">Full · all 65,535 ports, up to an hour</option>
                    </select>
                  </label>
                  <label>
                    <span className="label mb-1.5 block">Ports (optional)</span>
                    <input value={nmapPorts} onChange={(e) => setNmapPorts(e.target.value)} className="ctl w-full font-mono" placeholder="e.g. 22,80,443,8000-8100" pattern="[0-9,\- ]*" />
                  </label>
                </div>
              )}
              <p className="text-[12px] text-ink-faint">Browser capture is off: the engine container has no browser.</p>
            </div>
          )}

          <Toggle checked={archive} onChange={setArchive} label="Keep raw source answers" hint="Archive every third-party response for evidence (more disk)" />

          {error && (
            <p role="alert" className="rounded-ctl border border-down/30 bg-down/[0.07] px-3 py-2 text-[13.5px] text-down">
              {error}
            </p>
          )}
          <div className="flex items-center justify-end gap-3 border-t border-line pt-5">
            {viewer && <span className="mr-auto text-[13px] text-ink-muted">Viewers can read scans; starting one needs the analyst role.</span>}
            <button type="submit" className="btn-primary h-10 px-5" disabled={!canSubmit}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
              Start {mode === "Both" ? "passive + active" : mode.toLowerCase()} scan
            </button>
          </div>
        </form>
      </Card>
    </div>
  );
}
