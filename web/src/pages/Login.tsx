import { Loader2, LogIn } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Logo, PRODUCT } from "../components/ui";
import { safeNext } from "../lib/text";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  useEffect(() => {
    document.title = `Sign in · ${PRODUCT.name}`;
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const r = await fetch("/app/api/session", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ username, password }),
      });
      if (r.ok) {
        // A full load: the app starts fresh with the new session.
        window.location.assign(safeNext(new URLSearchParams(window.location.search).get("next")));
        return;
      }
      const data = await r.json().catch(() => ({}));
      setError(typeof data.detail === "string" ? data.detail : "Sign-in failed; try again.");
    } catch {
      setError("Can't reach the server; try again.");
    }
    setBusy(false);
  };

  return (
    <div className="relative flex min-h-full items-center justify-center overflow-hidden px-4 py-12">
      {/* a soft glow behind the card */}
      <div className="pointer-events-none absolute left-1/2 top-1/3 h-[480px] w-[720px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/10 blur-[120px]" aria-hidden="true" />
      <div className="relative w-full max-w-[400px]">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Logo size={56} />
          <div>
            <h1 className="text-[26px] font-bold tracking-tight">{PRODUCT.name}</h1>
            <p className="text-[13.5px] text-ink-muted">Attack surface and threat intelligence in one place</p>
          </div>
        </div>
        <form onSubmit={submit} className="card animate-rise space-y-4 p-6 sm:p-7" autoComplete="on">
          <h2 className="text-[16px] font-semibold">Sign in</h2>
          <label className="block">
            <span className="label mb-1.5 block">Username</span>
            <input value={username} onChange={(e) => setUsername(e.target.value)} className="ctl h-11 w-full" autoComplete="username" autoFocus required maxLength={200} />
          </label>
          <label className="block">
            <span className="label mb-1.5 block">Password</span>
            <input value={password} onChange={(e) => setPassword(e.target.value)} type="password" className="ctl h-11 w-full" autoComplete="current-password" required maxLength={1000} />
          </label>
          {error && (
            <p role="alert" className="rounded-ctl border border-down/30 bg-down/[0.07] px-3 py-2 text-[13px] text-down">
              {error}
            </p>
          )}
          <button className="btn-primary h-11 w-full text-[14.5px]" disabled={busy || !username || !password}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <LogIn className="h-4 w-4" />} Sign in
          </button>
          <p className="text-center text-[12px] text-ink-faint">
            No account? An admin creates one with <span className="font-mono">.\tl user NAME ROLE</span>
          </p>
        </form>
      </div>
    </div>
  );
}
