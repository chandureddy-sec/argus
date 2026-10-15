import { ArrowLeft, Eye, EyeOff, KeyRound, Loader2, LogIn, ShieldCheck } from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { Logo, PRODUCT } from "../components/ui";
import type { SsoProvider } from "../lib/api";
import { safeNext } from "../lib/text";

export default function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [ssoProviders, setSsoProviders] = useState<SsoProvider[]>([]);

  useEffect(() => {
    document.title = `Sign in · ${PRODUCT.name}`;
    fetch("/app/api/auth/sso/providers", { credentials: "same-origin" })
      .then((r) => (r.ok ? r.json() : []))
      .then((data: SsoProvider[]) => setSsoProviders(data))
      .catch(() => undefined);
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const payload: Record<string, string> = { username, password };
      if (needTotp && totpCode) {
        payload.totp_code = totpCode.trim();
      }
      const r = await fetch("/app/api/session", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(payload),
      });

      const data = await r.json().catch(() => ({}));
      if (r.ok) {
        if (data.totp_required) {
          setNeedTotp(true);
          setBusy(false);
          return;
        }
        // A full load: the app starts fresh with the new session.
        window.location.assign(safeNext(new URLSearchParams(window.location.search).get("next")));
        return;
      }
      setError(typeof data.detail === "string" ? data.detail : "Sign-in failed; try again.");
    } catch {
      setError("Can't reach the server; try again.");
    }
    setBusy(false);
  };

  const handleSsoClick = async (provider: SsoProvider) => {
    // For quick mock SSO in dev/demo or redirect to OAuth login
    const email = window.prompt(`Sign in with ${provider.name} (enter your corporate email):`);
    if (!email) return;
    setBusy(true);
    setError(undefined);
    try {
      const r = await fetch("/app/api/auth/sso/mock", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ provider: provider.id, email: email.trim(), name: email.split("@")[0] }),
      });
      if (r.ok) {
        window.location.assign(safeNext(new URLSearchParams(window.location.search).get("next")));
        return;
      }
      const data = await r.json().catch(() => ({}));
      setError(typeof data.detail === "string" ? data.detail : "SSO authentication failed");
    } catch {
      setError("Can't complete SSO sign-in");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative flex min-h-full items-center justify-center overflow-hidden px-4 py-12">
      {/* a soft glow behind the card */}
      <div
        className="pointer-events-none absolute left-1/2 top-1/3 h-[480px] w-[720px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-accent/10 blur-[120px]"
        aria-hidden="true"
      />
      <div className="relative w-full max-w-[420px]">
        <div className="mb-8 flex flex-col items-center gap-3 text-center">
          <Logo size={56} />
          <div>
            <h1 className="text-[26px] font-bold tracking-tight">{PRODUCT.name}</h1>
            <p className="text-[13.5px] text-ink-muted">Attack surface and threat intelligence in one place</p>
          </div>
        </div>

        <div className="card animate-rise space-y-4 p-6 sm:p-7">
          {!needTotp ? (
            <form onSubmit={submit} className="space-y-4" autoComplete="on">
              <h2 className="text-[16px] font-semibold">Sign in</h2>
              <label className="block">
                <span className="label mb-1.5 block">Username</span>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="ctl h-11 w-full"
                  autoComplete="username"
                  autoFocus
                  required
                  maxLength={200}
                />
              </label>
              <label className="block">
                <span className="label mb-1.5 block">Password</span>
                <span className="relative block">
                  <input
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    type={show ? "text" : "password"}
                    className="ctl h-11 w-full pr-11"
                    autoComplete="current-password"
                    autoCapitalize="off"
                    autoCorrect="off"
                    spellCheck={false}
                    required
                    maxLength={1000}
                  />
                  <button
                    type="button"
                    onClick={() => setShow((v) => !v)}
                    className="absolute right-1.5 top-1/2 inline-flex h-8 w-8 -translate-y-1/2 items-center justify-center rounded-ctl text-ink-muted hover:bg-card-2 hover:text-ink"
                    aria-label={show ? "Hide password" : "Show password"}
                    aria-pressed={show}
                    title={show ? "Hide password" : "Show password"}
                  >
                    {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </span>
              </label>

              {error && (
                <p role="alert" className="rounded-ctl border border-down/30 bg-down/[0.07] px-3 py-2 text-[13px] text-down">
                  {error}
                </p>
              )}

              <button className="btn-primary h-11 w-full text-[14.5px]" disabled={busy || !username || !password}>
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <LogIn className="h-4 w-4" />} Sign in
              </button>

              {ssoProviders.length > 0 && (
                <div className="pt-2">
                  <div className="relative my-3">
                    <div className="absolute inset-0 flex items-center">
                      <div className="w-full border-t border-line" />
                    </div>
                    <div className="relative flex justify-center text-[12px]">
                      <span className="bg-card px-2 text-ink-faint">Or single sign-on</span>
                    </div>
                  </div>
                  <div className="grid gap-2">
                    {ssoProviders.map((p) => (
                      <button
                        key={p.id}
                        type="button"
                        onClick={() => handleSsoClick(p)}
                        className="btn-ghost h-10 w-full justify-center border border-line text-[13.5px] font-medium"
                      >
                        <ShieldCheck className="h-4 w-4 text-up" /> Continue with {p.name}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <p className="pt-1 text-center text-[12px] text-ink-faint">
                Need an account? Admins manage users in <span className="font-semibold text-ink">Settings</span>.
              </p>
            </form>
          ) : (
            <form onSubmit={submit} className="space-y-4" autoComplete="off">
              <div className="flex items-center gap-2.5">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-accent/15 text-accent">
                  <KeyRound className="h-5 w-5" />
                </div>
                <div>
                  <h2 className="text-[16px] font-semibold">Two-Factor Authentication</h2>
                  <p className="text-[12.5px] text-ink-muted">Enter the 6-digit code for {username}</p>
                </div>
              </div>

              <label className="block">
                <span className="label mb-1.5 block">Authenticator code</span>
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  className="ctl h-12 w-full text-center font-mono text-[22px] tracking-[0.35em]"
                  placeholder="000000"
                  autoFocus
                  required
                  maxLength={6}
                />
              </label>

              {error && (
                <p role="alert" className="rounded-ctl border border-down/30 bg-down/[0.07] px-3 py-2 text-[13px] text-down">
                  {error}
                </p>
              )}

              <button
                className="btn-primary h-11 w-full text-[14.5px]"
                disabled={busy || totpCode.trim().length !== 6}
              >
                {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Verify & Sign in
              </button>

              <button
                type="button"
                onClick={() => {
                  setNeedTotp(false);
                  setTotpCode("");
                  setError(undefined);
                }}
                className="btn-ghost h-9 w-full justify-center text-[13px]"
              >
                <ArrowLeft className="h-3.5 w-3.5" /> Back to username & password
              </button>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
