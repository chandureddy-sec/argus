import {
  AlertCircle,
  Check,
  CheckCircle2,
  Download,
  History,
  KeyRound,
  Loader2,
  Lock,
  Plus,
  RefreshCw,
  Save,
  Search,
  ShieldCheck,
  Sliders,
  Trash2,
  UserPlus,
  Users,
  X,
} from "lucide-react";
import { useEffect, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { CopyButton, Ioc } from "../components/intel";
import { Failed, Skeleton } from "../components/states";
import { Avatar, Card, CardHead, Overlay } from "../components/ui";
import {
  post,
  send,
  useApi,
  useDebounced,
  type AuditItem,
  type AuditResponse,
  type Me,
  type SsoConfig,
  type TwoFactorSetupData,
  type TwoFactorStatus,
  type UserItem,
} from "../lib/api";
import { ago } from "../lib/format";
import { usePage } from "../lib/page";

// ── Types for Existing Policy & Feeds ────────────────────────────────────────

interface Policy {
  known_bad_days: number;
  suspect_days: number;
  manual_days: number;
  known_bad_score: number;
  export_max_tlp: string;
  require_second_approver: boolean;
}

interface SettingsData {
  policy: Policy;
  exportTlps: string[];
  formats: string[];
  exported: Record<string, number>;
  base: string;
  canEdit: boolean;
  tokens: {
    id: number;
    name: string;
    prefix: string;
    createdBy: string;
    createdAt: string;
    lastUsedAt: string | null;
    revokedAt: string | null;
  }[];
}

interface Never {
  manual: { id: number; kind: string; value: string; reason: string; createdBy: string | null }[];
  own: { id: number; kind: string; value: string; reason: string }[];
  assets: Record<string, number>;
  resolvers: string[];
  canEdit: boolean;
}

const FORMAT_HINT: Record<string, string> = {
  "ip.txt": "IPs and CIDR ranges, one per line (firewall IP list)",
  "domain.txt": "domains (firewall domain list)",
  "url.txt": "URLs without scheme (firewall URL list)",
  "blocks.csv": "every field, for spreadsheets and SIEM lookups",
  "blocks.json": "every field, for scripts",
  "stix.json": "STIX 2.1 bundle, TLP-marked",
};

const TLP_OPTIONS = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"];

type Tab = "users" | "security" | "audit" | "policy";

// ── 1. Team & User Management ────────────────────────────────────────────────

function TeamSection({ me }: { me?: Me }) {
  const { data: usersList, error, loading, reload } = useApi<UserItem[]>("settings/users");
  const [showCreate, setShowCreate] = useState(false);
  const [roleModalUser, setRoleModalUser] = useState<UserItem | null>(null);
  const [pwModalUser, setPwModalUser] = useState<UserItem | null>(null);

  // Create form state
  const [newName, setNewName] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState<"admin" | "analyst" | "viewer">("analyst");
  const [newClearance, setNewClearance] = useState<string>("TLP:AMBER");
  const [createBusy, setCreateBusy] = useState(false);
  const [createError, setCreateError] = useState<string>();

  // Role edit state
  const [editRole, setEditRole] = useState<"admin" | "analyst" | "viewer">("analyst");
  const [editClearance, setEditClearance] = useState<string>("TLP:AMBER");
  const [roleBusy, setRoleBusy] = useState(false);
  const [roleError, setRoleError] = useState<string>();

  // Password reset state
  const [resetPw, setResetPw] = useState("");
  const [pwBusy, setPwBusy] = useState(false);
  const [pwError, setPwError] = useState<string>();

  // General action state
  const [actionBusy, setActionBusy] = useState<string>();
  const [toast, setToast] = useState<{ ok: boolean; msg: string } | null>(null);

  const isAdmin = me?.role === "admin";

  const generateRandomPassword = () => {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*";
    let pwd = "";
    for (let i = 0; i < 16; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return pwd;
  };

  const handleCreateUser = async (e: FormEvent) => {
    e.preventDefault();
    setCreateBusy(true);
    setCreateError(undefined);
    try {
      await post("settings/users", {
        name: newName.trim(),
        password: newPassword,
        role: newRole,
        clearance: newClearance,
      });
      setShowCreate(false);
      setNewName("");
      setNewPassword("");
      setToast({ ok: true, msg: `User ${newName} created successfully.` });
      reload();
    } catch (err) {
      setCreateError((err as Error).message);
    } finally {
      setCreateBusy(false);
    }
  };

  const handleUpdateRole = async (e: FormEvent) => {
    e.preventDefault();
    if (!roleModalUser) return;
    setRoleBusy(true);
    setRoleError(undefined);
    try {
      await send("PATCH", `/app/api/settings/users/${roleModalUser.id}/role`, {
        role: editRole,
        clearance: editClearance,
      });
      setRoleModalUser(null);
      setToast({ ok: true, msg: `Updated permissions for ${roleModalUser.name}.` });
      reload();
    } catch (err) {
      setRoleError((err as Error).message);
    } finally {
      setRoleBusy(false);
    }
  };

  const handleResetPassword = async (e: FormEvent) => {
    e.preventDefault();
    if (!pwModalUser) return;
    setPwBusy(true);
    setPwError(undefined);
    try {
      await post(`settings/users/${pwModalUser.id}/password`, {
        password: resetPw,
      });
      setPwModalUser(null);
      setResetPw("");
      setToast({ ok: true, msg: `Password reset for ${pwModalUser.name}.` });
      reload();
    } catch (err) {
      setPwError((err as Error).message);
    } finally {
      setPwBusy(false);
    }
  };

  const handleToggleStatus = async (user: UserItem) => {
    const isDisable = !user.disabledAt;
    const confirmMsg = isDisable
      ? `Disable ${user.name}? They will immediately be signed out and unable to log in.`
      : `Re-enable ${user.name}'s account?`;
    if (!window.confirm(confirmMsg)) return;

    setActionBusy(`status-${user.id}`);
    try {
      const endpoint = isDisable ? "disable" : "enable";
      await post(`settings/users/${user.id}/${endpoint}`);
      setToast({ ok: true, msg: `Account ${isDisable ? "disabled" : "enabled"} for ${user.name}.` });
      reload();
    } catch (err) {
      setToast({ ok: false, msg: (err as Error).message });
    } finally {
      setActionBusy(undefined);
    }
  };

  const handleReset2Fa = async (user: UserItem) => {
    if (!window.confirm(`Reset Two-Factor Authentication for ${user.name}? This will clear their TOTP secret so they can sign in with their password and register a new authenticator device.`)) return;
    setActionBusy(`2fa-${user.id}`);
    try {
      await post(`settings/users/${user.id}/reset-2fa`);
      setToast({ ok: true, msg: `Two-factor authentication reset for ${user.name}.` });
      reload();
    } catch (err) {
      setToast({ ok: false, msg: (err as Error).message });
    } finally {
      setActionBusy(undefined);
    }
  };

  return (
    <Card>
      <CardHead
        title="Team & user management"
        sub={isAdmin ? "Create user accounts, manage roles, reset passwords, and disable accounts directly inside Argus." : "Read-only: only administrators can manage users."}
      >
        {isAdmin && (
          <button
            onClick={() => {
              setShowCreate(true);
              setNewPassword(generateRandomPassword());
              setCreateError(undefined);
            }}
            className="btn-primary"
          >
            <UserPlus className="h-4 w-4" /> Add user
          </button>
        )}
      </CardHead>

      {toast && (
        <div
          className={`mb-4 flex items-center justify-between rounded-ctl border px-3 py-2 text-[13px] ${
            toast.ok ? "border-up/30 bg-up/[0.08] text-up" : "border-down/30 bg-down/[0.08] text-down"
          }`}
        >
          <span className="flex items-center gap-2">
            {toast.ok ? <CheckCircle2 className="h-4 w-4" /> : <AlertCircle className="h-4 w-4" />}
            {toast.msg}
          </span>
          <button onClick={() => setToast(null)} className="text-ink-muted hover:text-ink">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {loading && !usersList ? (
        <Skeleton className="h-48" />
      ) : error ? (
        <Failed error={error} onRetry={reload} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left text-[13px]">
            <thead>
              <tr className="border-b border-line text-[12px] uppercase tracking-wider text-ink-faint">
                <th className="pb-3 pr-4 font-semibold">User</th>
                <th className="pb-3 pr-4 font-semibold">Role</th>
                <th className="pb-3 pr-4 font-semibold">TLP Clearance</th>
                <th className="pb-3 pr-4 font-semibold">Two-Factor</th>
                <th className="pb-3 pr-4 font-semibold">Status</th>
                <th className="pb-3 pr-4 font-semibold">Last sign-in</th>
                {isAdmin && <th className="pb-3 text-right font-semibold">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-line/70">
              {usersList?.map((u) => {
                const words = u.name.split(" ");
                const initials = (words[0][0] + (words[1]?.[0] || "")).toUpperCase();
                const isSelf = me?.name.toLowerCase() === u.name.toLowerCase();
                const isDisabled = Boolean(u.disabledAt);

                return (
                  <tr key={u.id} className={`transition-colors hover:bg-card-2/30 ${isDisabled ? "opacity-60" : ""}`}>
                    <td className="py-3.5 pr-4">
                      <div className="flex items-center gap-2.5">
                        <Avatar initials={initials} className="h-8 w-8 text-[11px]" />
                        <div>
                          <div className="font-semibold text-ink">
                            {u.name} {isSelf && <span className="text-[11px] text-accent-soft">(You)</span>}
                          </div>
                          <div className="font-mono text-[11.5px] text-ink-muted">@{u.login}</div>
                        </div>
                      </div>
                    </td>
                    <td className="py-3.5 pr-4">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11.5px] font-medium capitalize ${
                          u.role === "admin"
                            ? "bg-accent/15 text-accent-soft ring-1 ring-accent/30"
                            : u.role === "analyst"
                            ? "bg-up/15 text-up ring-1 ring-up/30"
                            : "bg-card-2 text-ink-muted ring-1 ring-line"
                        }`}
                      >
                        {u.role}
                      </span>
                    </td>
                    <td className="py-3.5 pr-4">
                      <span className="font-mono text-[12px] text-ink-muted">
                        {u.tlpClearance || "Role default"}
                      </span>
                    </td>
                    <td className="py-3.5 pr-4">
                      {u.totpEnabled ? (
                        <span className="inline-flex items-center gap-1.5 text-[12px] text-up">
                          <Check className="h-3.5 w-3.5" /> TOTP Active
                        </span>
                      ) : (
                        <span className="text-[12px] text-ink-faint">Disabled</span>
                      )}
                    </td>
                    <td className="py-3.5 pr-4">
                      {isDisabled ? (
                        <span className="inline-flex items-center rounded-full bg-down/15 px-2 py-0.5 text-[11px] font-semibold text-down ring-1 ring-down/30">
                          Disabled
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-[12px] text-up">
                          <span className="h-2 w-2 rounded-full bg-up" /> Active
                        </span>
                      )}
                    </td>
                    <td className="py-3.5 pr-4 text-ink-muted">{ago(u.lastLoginAt)}</td>
                    {isAdmin && (
                      <td className="py-3.5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => {
                              setRoleModalUser(u);
                              setEditRole(u.role);
                              setEditClearance(u.tlpClearance || "TLP:AMBER");
                              setRoleError(undefined);
                            }}
                            className="btn-ghost h-8 px-2.5 text-[12px]"
                            title="Change Role & Clearance"
                          >
                            Permissions
                          </button>
                          <button
                            onClick={() => {
                              setPwModalUser(u);
                              setResetPw(generateRandomPassword());
                              setPwError(undefined);
                            }}
                            className="btn-ghost h-8 px-2 text-[12px]"
                            title="Reset Password"
                          >
                            Password
                          </button>
                          {u.totpEnabled && (
                            <button
                              onClick={() => handleReset2Fa(u)}
                              disabled={actionBusy === `2fa-${u.id}`}
                              className="btn-ghost h-8 px-2 text-[12px] text-warn hover:!text-warn"
                              title="Reset 2FA Authenticator"
                            >
                              Reset 2FA
                            </button>
                          )}
                          {!isSelf && (
                            <button
                              onClick={() => handleToggleStatus(u)}
                              disabled={actionBusy === `status-${u.id}`}
                              className={`btn-ghost h-8 px-2 text-[12px] ${
                                isDisabled ? "text-up hover:!text-up" : "text-down hover:!text-down"
                              }`}
                            >
                              {isDisabled ? "Enable" : "Disable"}
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Modal: Add User */}
      {showCreate && (
        <Overlay>
          <div className="card w-full max-w-md animate-rise p-6 shadow-2xl">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-[16px] font-semibold">
                <UserPlus className="h-5 w-5 text-accent" /> Create user account
              </h3>
              <button onClick={() => setShowCreate(false)} className="text-ink-muted hover:text-ink">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleCreateUser} className="space-y-4">
              <label className="block">
                <span className="label mb-1.5 block">Full name / Username</span>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. Alice Cooper"
                  className="ctl w-full"
                  required
                  autoFocus
                  maxLength={64}
                />
              </label>

              <div className="grid gap-3 sm:grid-cols-2">
                <label className="block">
                  <span className="label mb-1.5 block">Role</span>
                  <select
                    value={newRole}
                    onChange={(e) => setNewRole(e.target.value as "admin" | "analyst" | "viewer")}
                    className="ctl w-full"
                  >
                    <option value="analyst">Analyst</option>
                    <option value="admin">Administrator</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </label>
                <label className="block">
                  <span className="label mb-1.5 block">TLP Clearance</span>
                  <select
                    value={newClearance}
                    onChange={(e) => setNewClearance(e.target.value)}
                    className="ctl w-full"
                  >
                    {TLP_OPTIONS.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                </label>
              </div>

              <label className="block">
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="label">Initial password</span>
                  <button
                    type="button"
                    onClick={() => setNewPassword(generateRandomPassword())}
                    className="flex items-center gap-1 text-[11.5px] text-accent-soft hover:underline"
                  >
                    <RefreshCw className="h-3 w-3" /> Generate
                  </button>
                </div>
                <input
                  type="text"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="ctl w-full font-mono text-[13px]"
                  required
                  minLength={6}
                />
                <span className="mt-1 block text-[11.5px] text-ink-faint">
                  Minimum 6 characters. Copy this password to provide to the user.
                </span>
              </label>

              {createError && (
                <p className="rounded-ctl border border-down/30 bg-down/[0.08] p-2 text-[12.5px] text-down">
                  {createError}
                </p>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowCreate(false)}
                  className="btn-ghost"
                  disabled={createBusy}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={createBusy}>
                  {createBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <UserPlus className="h-4 w-4" />} Create account
                </button>
              </div>
            </form>
          </div>
        </Overlay>
      )}

      {/* Modal: Change Role & Clearance */}
      {roleModalUser && (
        <Overlay>
          <div className="card w-full max-w-md animate-rise p-6 shadow-2xl">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="text-[16px] font-semibold">Change permissions: {roleModalUser.name}</h3>
              <button onClick={() => setRoleModalUser(null)} className="text-ink-muted hover:text-ink">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleUpdateRole} className="space-y-4">
              <label className="block">
                <span className="label mb-1.5 block">Role</span>
                <select
                  value={editRole}
                  onChange={(e) => setEditRole(e.target.value as "admin" | "analyst" | "viewer")}
                  className="ctl w-full"
                >
                  <option value="admin">Administrator (full access, enforce blocks, user settings)</option>
                  <option value="analyst">Analyst (scans, verify, cases, request enforce)</option>
                  <option value="viewer">Viewer (read-only monitoring within clearance)</option>
                </select>
              </label>
              <label className="block">
                <span className="label mb-1.5 block">TLP Clearance</span>
                <select
                  value={editClearance}
                  onChange={(e) => setEditClearance(e.target.value)}
                  className="ctl w-full"
                >
                  {TLP_OPTIONS.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
                <span className="mt-1 block text-[11.5px] text-ink-faint">
                  Maximum classification level this user can inspect.
                </span>
              </label>

              {roleError && (
                <p className="rounded-ctl border border-down/30 bg-down/[0.08] p-2 text-[12.5px] text-down">
                  {roleError}
                </p>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setRoleModalUser(null)}
                  className="btn-ghost"
                  disabled={roleBusy}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={roleBusy}>
                  {roleBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save changes
                </button>
              </div>
            </form>
          </div>
        </Overlay>
      )}

      {/* Modal: Reset Password */}
      {pwModalUser && (
        <Overlay>
          <div className="card w-full max-w-md animate-rise p-6 shadow-2xl">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="flex items-center gap-2 text-[16px] font-semibold">
                <Lock className="h-5 w-5 text-accent" /> Reset password: {pwModalUser.name}
              </h3>
              <button onClick={() => setPwModalUser(null)} className="text-ink-muted hover:text-ink">
                <X className="h-5 w-5" />
              </button>
            </div>
            <form onSubmit={handleResetPassword} className="space-y-4">
              <p className="text-[12.5px] text-ink-muted">
                Setting a new password will immediately revoke all current sign-in sessions for this user.
              </p>
              <label className="block">
                <div className="mb-1.5 flex items-center justify-between">
                  <span className="label">New password</span>
                  <button
                    type="button"
                    onClick={() => setResetPw(generateRandomPassword())}
                    className="flex items-center gap-1 text-[11.5px] text-accent-soft hover:underline"
                  >
                    <RefreshCw className="h-3 w-3" /> Generate
                  </button>
                </div>
                <input
                  type="text"
                  value={resetPw}
                  onChange={(e) => setResetPw(e.target.value)}
                  className="ctl w-full font-mono text-[13px]"
                  required
                  minLength={6}
                  autoFocus
                />
              </label>

              {pwError && (
                <p className="rounded-ctl border border-down/30 bg-down/[0.08] p-2 text-[12.5px] text-down">
                  {pwError}
                </p>
              )}

              <div className="flex items-center justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setPwModalUser(null)}
                  className="btn-ghost"
                  disabled={pwBusy}
                >
                  Cancel
                </button>
                <button type="submit" className="btn-primary" disabled={pwBusy}>
                  {pwBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Lock className="h-4 w-4" />} Set new password
                </button>
              </div>
            </form>
          </div>
        </Overlay>
      )}
    </Card>
  );
}

// ── 2. Two-Factor Authentication & SSO ────────────────────────────────────────

function SecuritySection({ me }: { me?: Me }) {
  const { data: status2Fa, reload: reload2Fa } = useApi<TwoFactorStatus>("settings/2fa");
  const { data: ssoConfig, reload: reloadSso } = useApi<SsoConfig>("settings/sso");

  // 2FA Setup Wizard
  const [setupData, setSetupData] = useState<TwoFactorSetupData | null>(null);
  const [verifyCode, setVerifyCode] = useState("");
  const [setupBusy, setSetupBusy] = useState(false);
  const [setupError, setSetupError] = useState<string>();
  const [showDisableModal, setShowDisableModal] = useState(false);
  const [disableCode, setDisableCode] = useState("");
  const [disableBusy, setDisableBusy] = useState(false);
  const [disableError, setDisableError] = useState<string>();

  // SSO Form State
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [ssoDefaultRole, setSsoDefaultRole] = useState<"admin" | "analyst" | "viewer">("analyst");
  const [ssoAutoProvision, setSsoAutoProvision] = useState(true);

  // Providers
  const [googleEnabled, setGoogleEnabled] = useState(false);
  const [googleClientId, setGoogleClientId] = useState("");
  const [googleClientSecret, setGoogleClientSecret] = useState("");
  const [googleHd, setGoogleHd] = useState("");

  const [msEnabled, setMsEnabled] = useState(false);
  const [msClientId, setMsClientId] = useState("");
  const [msClientSecret, setMsClientSecret] = useState("");
  const [msTenant, setMsTenant] = useState("common");

  const [oktaEnabled, setOktaEnabled] = useState(false);
  const [oktaClientId, setOktaClientId] = useState("");
  const [oktaClientSecret, setOktaClientSecret] = useState("");
  const [oktaDomain, setOktaDomain] = useState("");

  const [ssoBusy, setSsoBusy] = useState(false);
  const [ssoMsg, setSsoMsg] = useState<{ ok: boolean; text: string }>();

  const isAdmin = me?.role === "admin";

  useEffect(() => {
    if (ssoConfig) {
      setSsoEnabled(Boolean(ssoConfig.enabled));
      setSsoDefaultRole(ssoConfig.default_role || "analyst");
      setSsoAutoProvision(ssoConfig.auto_provision !== false);

      const g = ssoConfig.providers?.google;
      setGoogleEnabled(Boolean(g?.enabled));
      setGoogleClientId(g?.client_id || "");
      setGoogleClientSecret(g?.client_secret || "");
      setGoogleHd(g?.hosted_domain || "");

      const m = ssoConfig.providers?.microsoft;
      setMsEnabled(Boolean(m?.enabled));
      setMsClientId(m?.client_id || "");
      setMsClientSecret(m?.client_secret || "");
      setMsTenant(m?.tenant || "common");

      const o = ssoConfig.providers?.okta;
      setOktaEnabled(Boolean(o?.enabled));
      setOktaClientId(o?.client_id || "");
      setOktaClientSecret(o?.client_secret || "");
      setOktaDomain(o?.domain || "");
    }
  }, [ssoConfig]);

  const start2FaSetup = async () => {
    setSetupBusy(true);
    setSetupError(undefined);
    try {
      const data = await post<TwoFactorSetupData>("settings/2fa/setup");
      setSetupData(data);
      setVerifyCode("");
    } catch (err) {
      setSetupError((err as Error).message);
    } finally {
      setSetupBusy(false);
    }
  };

  const confirm2Fa = async (e: FormEvent) => {
    e.preventDefault();
    if (!setupData) return;
    setSetupBusy(true);
    setSetupError(undefined);
    try {
      await post("settings/2fa/enable", {
        secret: setupData.secret,
        code: verifyCode.trim(),
      });
      setSetupData(null);
      setVerifyCode("");
      reload2Fa();
    } catch (err) {
      setSetupError((err as Error).message);
    } finally {
      setSetupBusy(false);
    }
  };

  const handleDisable2Fa = async (e: FormEvent) => {
    e.preventDefault();
    setDisableBusy(true);
    setDisableError(undefined);
    try {
      await post("settings/2fa/disable", {
        code: disableCode.trim(),
      });
      setShowDisableModal(false);
      setDisableCode("");
      reload2Fa();
    } catch (err) {
      setDisableError((err as Error).message);
    } finally {
      setDisableBusy(false);
    }
  };

  const saveSso = async (e: FormEvent) => {
    e.preventDefault();
    setSsoBusy(true);
    setSsoMsg(undefined);
    try {
      await send("PUT", "/app/api/settings/sso", {
        enabled: ssoEnabled,
        default_role: ssoDefaultRole,
        auto_provision: ssoAutoProvision,
        providers: {
          google: {
            enabled: googleEnabled,
            client_id: googleClientId.trim(),
            client_secret: googleClientSecret.trim(),
            hosted_domain: googleHd.trim(),
          },
          microsoft: {
            enabled: msEnabled,
            client_id: msClientId.trim(),
            client_secret: msClientSecret.trim(),
            tenant: msTenant.trim(),
          },
          okta: {
            enabled: oktaEnabled,
            client_id: oktaClientId.trim(),
            client_secret: oktaClientSecret.trim(),
            domain: oktaDomain.trim(),
          },
        },
      });
      setSsoMsg({ ok: true, text: "SSO settings saved." });
      reloadSso();
    } catch (err) {
      setSsoMsg({ ok: false, text: (err as Error).message });
    } finally {
      setSsoBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 2FA Card */}
      <Card>
        <CardHead
          title="Two-factor authentication (TOTP)"
          sub="Protect your account with a time-based one-time password from an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, etc.)."
        />

        {status2Fa?.enabled ? (
          <div className="rounded-card border border-up/30 bg-up/[0.06] p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-up/15 text-up">
                  <ShieldCheck className="h-6 w-6" />
                </div>
                <div>
                  <h4 className="font-semibold text-ink">Two-factor sign-in is active</h4>
                  <p className="text-[12.5px] text-ink-muted">
                    Your account requires a 6-digit verification code on sign-in.
                    {status2Fa.enabledAt && ` Active since ${ago(status2Fa.enabledAt)}.`}
                  </p>
                </div>
              </div>
              <button
                onClick={() => {
                  setShowDisableModal(true);
                  setDisableError(undefined);
                  setDisableCode("");
                }}
                className="btn-ghost text-down hover:!text-down"
              >
                Disable 2FA
              </button>
            </div>
          </div>
        ) : (
          <div className="rounded-card border border-line bg-card-2/30 p-5">
            <div className="flex flex-wrap items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-full bg-card text-ink-muted">
                  <KeyRound className="h-5 w-5" />
                </div>
                <div>
                  <h4 className="font-semibold text-ink">Two-factor sign-in is not enabled</h4>
                  <p className="text-[12.5px] text-ink-muted">
                    We recommend enabling TOTP two-factor authentication to secure against credential stuffing.
                  </p>
                </div>
              </div>
              <button onClick={start2FaSetup} className="btn-primary" disabled={setupBusy}>
                {setupBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />} Set up 2FA
              </button>
            </div>
          </div>
        )}

        {/* 2FA Setup Modal */}
        {setupData && (
          <Overlay>
            <div className="card w-full max-w-lg animate-rise p-6 shadow-2xl">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="flex items-center gap-2 text-[16px] font-semibold">
                  <KeyRound className="h-5 w-5 text-accent" /> Set up Two-Factor Authentication
                </h3>
                <button onClick={() => setSetupData(null)} className="text-ink-muted hover:text-ink">
                  <X className="h-5 w-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <p className="text-[13px] font-semibold text-ink">Step 1: Scan this QR code</p>
                  <p className="text-[12.5px] text-ink-muted">
                    Open Google Authenticator, Microsoft Authenticator, or 1Password and scan:
                  </p>
                </div>

                <div className="flex flex-col items-center justify-center rounded-card bg-white p-4">
                  <div
                    className="h-48 w-48 [&_svg]:h-full [&_svg]:w-full"
                    dangerouslySetInnerHTML={{ __html: setupData.qr_svg }}
                  />
                </div>

                <div>
                  <span className="label mb-1 block">Manual entry key</span>
                  <div className="flex items-center gap-2 rounded-ctl border border-line bg-card p-2 font-mono text-[13px]">
                    <span className="flex-1 select-all tracking-wider text-ink">{setupData.secret}</span>
                    <CopyButton value={setupData.secret} />
                  </div>
                </div>

                <form onSubmit={confirm2Fa} className="space-y-3 pt-2">
                  <div>
                    <label className="label mb-1.5 block">Step 2: Enter 6-digit code to verify</label>
                    <input
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      value={verifyCode}
                      onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                      className="ctl h-11 w-full text-center font-mono text-[18px] tracking-[0.25em]"
                      placeholder="000000"
                      maxLength={6}
                      required
                      autoFocus
                    />
                  </div>

                  {setupError && (
                    <p className="rounded-ctl border border-down/30 bg-down/[0.08] p-2 text-[12.5px] text-down">
                      {setupError}
                    </p>
                  )}

                  <div className="flex items-center justify-end gap-2 pt-2">
                    <button
                      type="button"
                      onClick={() => setSetupData(null)}
                      className="btn-ghost"
                      disabled={setupBusy}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={setupBusy || verifyCode.trim().length !== 6}
                    >
                      {setupBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4" />} Activate 2FA
                    </button>
                  </div>
                </form>
              </div>
            </div>
          </Overlay>
        )}

        {/* Modal: Disable 2FA */}
        {showDisableModal && (
          <Overlay>
            <div className="card w-full max-w-md animate-rise p-6 shadow-2xl">
              <div className="mb-4 flex items-center justify-between">
                <h3 className="text-[16px] font-semibold text-down">Disable Two-Factor Authentication</h3>
                <button onClick={() => setShowDisableModal(false)} className="text-ink-muted hover:text-ink">
                  <X className="h-5 w-5" />
                </button>
              </div>
              <form onSubmit={handleDisable2Fa} className="space-y-4">
                <p className="text-[12.5px] text-ink-muted">
                  To confirm, enter the 6-digit code currently showing in your authenticator app:
                </p>
                <input
                  type="text"
                  inputMode="numeric"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, "").slice(0, 6))}
                  className="ctl h-11 w-full text-center font-mono text-[18px] tracking-[0.25em]"
                  placeholder="000000"
                  maxLength={6}
                  required
                  autoFocus
                />
                {disableError && (
                  <p className="rounded-ctl border border-down/30 bg-down/[0.08] p-2 text-[12.5px] text-down">
                    {disableError}
                  </p>
                )}
                <div className="flex items-center justify-end gap-2 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowDisableModal(false)}
                    className="btn-ghost"
                    disabled={disableBusy}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn-primary !bg-down hover:!bg-down/90"
                    disabled={disableBusy || disableCode.length !== 6}
                  >
                    {disableBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : "Confirm disable"}
                  </button>
                </div>
              </form>
            </div>
          </Overlay>
        )}
      </Card>

      {/* SSO Card */}
      <Card>
        <CardHead
          title="Single sign-on (SSO)"
          sub={isAdmin ? "Configure OAuth2 / OIDC providers (Google Workspace, Microsoft Entra ID, Okta) for team sign-in." : "Read-only: only administrators can configure SSO."}
        />

        <form onSubmit={saveSso} className="space-y-6">
          <fieldset disabled={!isAdmin || ssoBusy} className="space-y-6">
            <div className="flex flex-wrap items-center justify-between gap-4 rounded-ctl border border-line bg-card-2/30 p-4">
              <div>
                <span className="text-[14px] font-semibold text-ink">Enable Single Sign-On</span>
                <p className="text-[12.5px] text-ink-muted">Allow analysts to sign in via configured identity providers.</p>
              </div>
              <label className="relative inline-flex cursor-pointer items-center">
                <input
                  type="checkbox"
                  checked={ssoEnabled}
                  onChange={(e) => setSsoEnabled(e.target.checked)}
                  className="sr-only peer"
                />
                <div className="h-6 w-11 rounded-full bg-ctl-line peer-checked:bg-accent after:absolute after:top-[2px] after:left-[2px] after:h-5 after:w-5 after:rounded-full after:bg-knob after:transition-all peer-checked:after:translate-x-full" />
              </label>
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <label className="block">
                <span className="label mb-1.5 block">Default role for new SSO users</span>
                <select
                  value={ssoDefaultRole}
                  onChange={(e) => setSsoDefaultRole(e.target.value as "admin" | "analyst" | "viewer")}
                  className="ctl w-full"
                >
                  <option value="analyst">Analyst</option>
                  <option value="viewer">Viewer</option>
                  <option value="admin">Administrator</option>
                </select>
              </label>
              <label className="flex items-center gap-2 self-end pb-2.5 text-[13.5px]">
                <input
                  type="checkbox"
                  checked={ssoAutoProvision}
                  onChange={(e) => setSsoAutoProvision(e.target.checked)}
                  className="h-4 w-4 accent-accent"
                />
                Auto-provision accounts on first sign-in
              </label>
            </div>

            {/* Providers */}
            <div className="space-y-4">
              {/* Google */}
              <div className="rounded-card border border-line bg-card-2/20 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-ink">Google Workspace / Cloud Identity</span>
                  </div>
                  <label className="flex items-center gap-2 text-[12.5px]">
                    <input
                      type="checkbox"
                      checked={googleEnabled}
                      onChange={(e) => setGoogleEnabled(e.target.checked)}
                      className="h-4 w-4 accent-accent"
                    />
                    Enabled
                  </label>
                </div>
                {googleEnabled && (
                  <div className="grid gap-3 pt-2 sm:grid-cols-3">
                    <input
                      type="text"
                      placeholder="OAuth Client ID"
                      value={googleClientId}
                      onChange={(e) => setGoogleClientId(e.target.value)}
                      className="ctl"
                    />
                    <input
                      type="password"
                      placeholder="OAuth Client Secret"
                      value={googleClientSecret}
                      onChange={(e) => setGoogleClientSecret(e.target.value)}
                      className="ctl"
                    />
                    <input
                      type="text"
                      placeholder="Restricted Domain (e.g. corp.com)"
                      value={googleHd}
                      onChange={(e) => setGoogleHd(e.target.value)}
                      className="ctl"
                    />
                  </div>
                )}
              </div>

              {/* Microsoft */}
              <div className="rounded-card border border-line bg-card-2/20 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-ink">Microsoft Entra ID (Azure AD)</span>
                  </div>
                  <label className="flex items-center gap-2 text-[12.5px]">
                    <input
                      type="checkbox"
                      checked={msEnabled}
                      onChange={(e) => setMsEnabled(e.target.checked)}
                      className="h-4 w-4 accent-accent"
                    />
                    Enabled
                  </label>
                </div>
                {msEnabled && (
                  <div className="grid gap-3 pt-2 sm:grid-cols-3">
                    <input
                      type="text"
                      placeholder="Application (Client) ID"
                      value={msClientId}
                      onChange={(e) => setMsClientId(e.target.value)}
                      className="ctl"
                    />
                    <input
                      type="password"
                      placeholder="Client Secret"
                      value={msClientSecret}
                      onChange={(e) => setMsClientSecret(e.target.value)}
                      className="ctl"
                    />
                    <input
                      type="text"
                      placeholder="Directory (Tenant) ID or common"
                      value={msTenant}
                      onChange={(e) => setMsTenant(e.target.value)}
                      className="ctl"
                    />
                  </div>
                )}
              </div>

              {/* Okta */}
              <div className="rounded-card border border-line bg-card-2/20 p-4">
                <div className="mb-3 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-ink">Okta OIDC</span>
                  </div>
                  <label className="flex items-center gap-2 text-[12.5px]">
                    <input
                      type="checkbox"
                      checked={oktaEnabled}
                      onChange={(e) => setOktaEnabled(e.target.checked)}
                      className="h-4 w-4 accent-accent"
                    />
                    Enabled
                  </label>
                </div>
                {oktaEnabled && (
                  <div className="grid gap-3 pt-2 sm:grid-cols-3">
                    <input
                      type="text"
                      placeholder="Client ID"
                      value={oktaClientId}
                      onChange={(e) => setOktaClientId(e.target.value)}
                      className="ctl"
                    />
                    <input
                      type="password"
                      placeholder="Client Secret"
                      value={oktaClientSecret}
                      onChange={(e) => setOktaClientSecret(e.target.value)}
                      className="ctl"
                    />
                    <input
                      type="text"
                      placeholder="Okta Domain (e.g. dev-123.okta.com)"
                      value={oktaDomain}
                      onChange={(e) => setOktaDomain(e.target.value)}
                      className="ctl"
                    />
                  </div>
                )}
              </div>
            </div>
          </fieldset>

          {isAdmin && (
            <div className="flex items-center gap-3">
              <button className="btn-primary" disabled={ssoBusy}>
                {ssoBusy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save SSO settings
              </button>
              {ssoMsg && (
                <span className={`text-[13px] ${ssoMsg.ok ? "text-up" : "text-down"}`}>
                  {ssoMsg.text}
                </span>
              )}
            </div>
          )}
        </form>
      </Card>
    </div>
  );
}

// ── 3. Audit Log Viewer ──────────────────────────────────────────────────────

function AuditLogSection() {
  const [query, setQuery] = useState("");
  const debouncedQuery = useDebounced(query, 300);
  const [category, setCategory] = useState("all");
  const [actor, setActor] = useState("");
  const [inspectItem, setInspectItem] = useState<AuditItem | null>(null);

  const { data, loading, error, reload } = useApi<AuditResponse>("settings/audit", {
    q: debouncedQuery || undefined,
    category: category !== "all" ? category : undefined,
    actor: actor || undefined,
  });

  const getBadgeStyle = (action: string) => {
    if (action.startsWith("block.approve") || action.startsWith("block.enforce")) {
      return "bg-accent/15 text-accent-soft ring-1 ring-accent/30";
    }
    if (action.startsWith("block.create") || action.startsWith("block.")) {
      return "bg-warn/15 text-warn ring-1 ring-warn/30";
    }
    if (action.startsWith("recon.")) {
      return "bg-teal/15 text-teal ring-1 ring-teal/30";
    }
    if (action.startsWith("user.create") || action.startsWith("user.sso")) {
      return "bg-up/15 text-up ring-1 ring-up/30";
    }
    if (action.startsWith("user.disable") || action.startsWith("user.totp_reset")) {
      return "bg-down/15 text-down ring-1 ring-down/30";
    }
    if (action.startsWith("user.")) {
      return "bg-plum/15 text-plum ring-1 ring-plum/30";
    }
    if (action.startsWith("settings.") || action.startsWith("feed_token.")) {
      return "bg-terracotta/15 text-terracotta ring-1 ring-terracotta/30";
    }
    return "bg-card-2 text-ink-muted ring-1 ring-line";
  };

  const formatSummary = (action: string, target: string, details: Record<string, unknown>) => {
    if (action === "block.create") {
      return `Created block for ${details.value || target} (${details.days || 30} days)`;
    }
    if (action === "block.approve") {
      return `Approved enforce block requested by ${details.requested_by || "analyst"}`;
    }
    if (action === "block.enforce") {
      return `Enforced block on ${details.value || target}`;
    }
    if (action === "block.decline") {
      return `Declined enforce block request`;
    }
    if (action === "block.lift") {
      return `Lifted block`;
    }
    if (action === "recon.scan") {
      return `Initiated scan on ${target} (mode: ${details.mode || "passive"})`;
    }
    if (action === "user.create") {
      return `Created user account with role: ${details.role || "analyst"}`;
    }
    if (action === "user.role") {
      return `Changed role: ${details.from} -> ${details.to}`;
    }
    if (action === "user.password") {
      return `Reset password`;
    }
    if (action === "user.disable") {
      return `Disabled account`;
    }
    if (action === "user.enable") {
      return `Re-enabled account`;
    }
    if (action === "user.totp_enable") {
      return `Enabled TOTP two-factor authentication`;
    }
    if (action === "user.totp_disable") {
      return `Disabled TOTP two-factor authentication`;
    }
    if (action === "user.totp_reset") {
      return `Administrator reset user's TOTP configuration`;
    }
    if (action === "user.sso_login") {
      return `Signed in via SSO (${details.provider})`;
    }
    if (action === "user.sso_provision") {
      return `Auto-provisioned SSO user account via ${details.provider}`;
    }
    if (action === "settings.sso_update") {
      return `Updated SSO identity provider settings`;
    }
    if (action === "settings.update") {
      return `Updated blocking policy settings`;
    }
    if (action === "allowlist.add") {
      return `Added ${target} to never-block list`;
    }
    if (action === "allowlist.remove") {
      return `Removed ${target} from never-block list`;
    }
    if (action === "feed_token.create") {
      return `Generated feed export token for ${details.name || target}`;
    }
    return Object.keys(details).length ? JSON.stringify(details).slice(0, 80) : "No details recorded";
  };

  const exportUrl = `/app/api/settings/audit/export?category=${category}&actor=${actor}&q=${encodeURIComponent(debouncedQuery)}`;

  return (
    <Card>
      <CardHead
        title="Audit log viewer"
        sub="Searchable, tamper-evident audit record of who blocked, approved, scanned, or changed what across Argus."
      >
        <div className="flex items-center gap-2">
          <a
            href={exportUrl}
            download
            className="btn-ghost h-9 px-3 text-[13px]"
            title="Download audit records as CSV"
          >
            <Download className="h-4 w-4" /> Export CSV
          </a>
          <button onClick={reload} className="btn-ghost h-9 px-2 text-[13px]" title="Refresh audit log">
            <RefreshCw className="h-4 w-4" />
          </button>
        </div>
      </CardHead>

      {/* Category Pills */}
      <div className="mb-4 flex flex-wrap items-center gap-1.5 border-b border-line pb-3">
        {data?.categories.map((c) => (
          <button
            key={c.id}
            onClick={() => setCategory(c.id)}
            className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-[12.5px] font-medium transition-colors ${
              category === c.id
                ? "bg-accent text-on-accent shadow-glow"
                : "bg-card-2/60 text-ink-muted hover:bg-card-2 hover:text-ink"
            }`}
          >
            <span>{c.label}</span>
            <span
              className={`rounded-full px-1.5 py-0.2 text-[11px] tabular-nums ${
                category === c.id ? "bg-on-accent/15 text-on-accent" : "bg-card text-ink-faint"
              }`}
            >
              {c.count}
            </span>
          </button>
        ))}
      </div>

      {/* Filter and Search Bar */}
      <div className="mb-4 grid gap-2.5 sm:grid-cols-[1fr_auto]">
        <div className="relative">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by actor, action, target IP/domain, or change details..."
            className="ctl h-10 w-full pl-9 pr-3"
          />
        </div>

        <select
          value={actor}
          onChange={(e) => setActor(e.target.value)}
          className="ctl h-10 min-w-[160px]"
        >
          <option value="">All actors</option>
          {data?.actors.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </div>

      {loading && !data ? (
        <Skeleton className="h-64" />
      ) : error ? (
        <Failed error={error} onRetry={reload} />
      ) : (
        <div>
          <div className="mb-2 text-[12.5px] text-ink-muted">
            Found <b className="text-ink">{data?.total ?? 0}</b> matching event
            {data?.total === 1 ? "" : "s"}
          </div>

          <div className="overflow-x-auto rounded-ctl border border-line">
            <table className="w-full text-left text-[13px]">
              <thead className="bg-card-2/50 text-[12px] uppercase tracking-wider text-ink-faint">
                <tr className="border-b border-line">
                  <th className="py-2.5 px-3 font-semibold">Time</th>
                  <th className="py-2.5 px-3 font-semibold">Actor</th>
                  <th className="py-2.5 px-3 font-semibold">Action</th>
                  <th className="py-2.5 px-3 font-semibold">Target</th>
                  <th className="py-2.5 px-3 font-semibold">Details</th>
                  <th className="py-2.5 px-3 text-right font-semibold">JSON</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line/70">
                {data?.items.map((row) => (
                  <tr key={row.id} className="transition-colors hover:bg-card-2/40">
                    <td className="whitespace-nowrap py-2.5 px-3 text-ink-muted" title={row.at}>
                      {ago(row.at)}
                    </td>
                    <td className="whitespace-nowrap py-2.5 px-3">
                      <span className="font-medium text-ink">{row.actor}</span>
                    </td>
                    <td className="whitespace-nowrap py-2.5 px-3">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-mono font-medium ${getBadgeStyle(
                          row.action
                        )}`}
                      >
                        {row.action}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[12px] text-ink">
                      {row.target ? <Ioc value={row.target} /> : <span className="text-ink-faint">—</span>}
                    </td>
                    <td className="py-2.5 px-3 text-[12.5px] text-ink-muted">
                      {formatSummary(row.action, row.target, row.details)}
                    </td>
                    <td className="whitespace-nowrap py-2.5 px-3 text-right">
                      <button
                        onClick={() => setInspectItem(row)}
                        className="btn-ghost h-7 px-2 text-[11.5px]"
                        title="View raw JSON audit record"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
                {data?.items.length === 0 && (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-ink-muted">
                      No audit events match your filter criteria.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modal: JSON Details Inspector */}
      {inspectItem && (
        <Overlay>
          <div className="card w-full max-w-lg animate-rise p-6 shadow-2xl">
            <div className="mb-3 flex items-center justify-between">
              <div>
                <h3 className="font-semibold text-ink">Audit Event #{inspectItem.id}</h3>
                <span className="font-mono text-[12px] text-ink-muted">{inspectItem.at}</span>
              </div>
              <button onClick={() => setInspectItem(null)} className="text-ink-muted hover:text-ink">
                <X className="h-5 w-5" />
              </button>
            </div>
            <div className="mb-4 space-y-2 text-[13px]">
              <div>
                <span className="label">Actor:</span> <b>{inspectItem.actor}</b>
              </div>
              <div>
                <span className="label">Action:</span> <span className="font-mono text-accent-soft">{inspectItem.action}</span>
              </div>
              <div>
                <span className="label">Target:</span> <span className="font-mono">{inspectItem.target || "none"}</span>
              </div>
            </div>
            <div className="rounded-card border border-line bg-card p-3">
              <span className="label mb-1 block">Full Details payload</span>
              <pre className="max-h-60 overflow-auto font-mono text-[12px] text-ink">
                {JSON.stringify(inspectItem.details, null, 2)}
              </pre>
            </div>
            <div className="mt-4 flex justify-end">
              <button onClick={() => setInspectItem(null)} className="btn-primary">
                Close
              </button>
            </div>
          </div>
        </Overlay>
      )}
    </Card>
  );
}

// ── 4. Policy, Feeds & Allowlist Cards (Preserved) ───────────────────────────

function PolicyCard({ s, reload }: { s: SettingsData; reload: () => void }) {
  const [p, setP] = useState<Policy>(s.policy);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string }>();
  useEffect(() => setP(s.policy), [s.policy]);
  const save = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(undefined);
    try {
      await send("PUT", "/app/api/settings/policy", {
        ...p,
        known_bad_days: Number(p.known_bad_days),
        suspect_days: Number(p.suspect_days),
        manual_days: Number(p.manual_days),
        known_bad_score: Number(p.known_bad_score),
      });
      setMsg({ ok: true, text: "Saved" });
      reload();
    } catch (err) {
      setMsg({ ok: false, text: (err as Error).message });
    } finally {
      setBusy(false);
    }
  };
  const num = (k: keyof Policy, label: string, min: number, max: number) => (
    <label className="block">
      <span className="label mb-1.5 block">{label}</span>
      <input
        type="number"
        min={min}
        max={max}
        value={p[k] as number}
        onChange={(e) => setP({ ...p, [k]: e.target.value })}
        className="ctl w-full"
        required
      />
    </label>
  );
  return (
    <Card>
      <CardHead
        title="Blocking policy"
        sub={s.canEdit ? "How long blocks last and who may enforce them" : "Read only: changes need the admin role"}
      />
      <form onSubmit={save} className="space-y-4">
        <fieldset disabled={!s.canEdit || busy} className="grid gap-4 sm:grid-cols-2">
          {num("known_bad_days", "Known-bad block (days)", 1, 365)}
          {num("suspect_days", "Suspect block (days)", 1, 365)}
          {num("manual_days", "Manual block (days)", 1, 365)}
          {num("known_bad_score", "Known-bad from score", 0, 100)}
          <label className="block">
            <span className="label mb-1.5 block">Export up to</span>
            <select
              value={p.export_max_tlp}
              onChange={(e) => setP({ ...p, export_max_tlp: e.target.value })}
              className="ctl w-full"
            >
              {s.exportTlps.map((t) => (
                <option key={t}>{t}</option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-2 self-end pb-2 text-[13.5px]">
            <input
              type="checkbox"
              className="h-4 w-4 accent-accent"
              checked={p.require_second_approver}
              onChange={(e) => setP({ ...p, require_second_approver: e.target.checked })}
            />{" "}
            Enforcing needs a second admin
          </label>
        </fieldset>
        <ul className="space-y-1 text-[12.5px] text-ink-muted">
          <li>
            <b className="text-ink">Known bad</b>: an active indicator at or above the score.{" "}
            <b className="text-ink">Manual</b>: typed into the blocklist.{" "}
            <b className="text-ink">Suspect</b>: everything else.
          </li>
          <li>
            <b className="text-ink">Second admin</b>: whoever asks for enforce can't approve it. Turn off only if you are the sole admin.
          </li>
          <li>
            <b className="text-ink">Export up to</b>: blocks marked above this never reach a device. TLP:RED is never exported.
          </li>
        </ul>
        {s.canEdit && (
          <div className="flex items-center gap-3">
            <button className="btn-primary" disabled={busy}>
              {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />} Save policy
            </button>
            {msg && <span className={`text-[13px] ${msg.ok ? "text-up" : "text-down"}`}>{msg.text}</span>}
          </div>
        )}
      </form>
    </Card>
  );
}

function ExportCard({ s, reload }: { s: SettingsData; reload: () => void }) {
  const [name, setName] = useState("");
  const [busy, setBusy] = useState<string>();
  const [made, setMade] = useState<{ name: string; token: string; urls: string[] }>();
  const [error, setError] = useState<string>();
  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy("new");
    setError(undefined);
    try {
      setMade(await post("settings/tokens", { name }));
      setName("");
      reload();
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  const revoke = async (id: number) => {
    if (!window.confirm("Revoke this token? Devices using it stop getting updates at once.")) return;
    setBusy(String(id));
    try {
      await post(`settings/tokens/${id}/revoke`);
      reload();
    } finally {
      setBusy(undefined);
    }
  };
  const ips = (s.exported.ip ?? 0) + (s.exported.cidr ?? 0);
  return (
    <Card>
      <CardHead
        title="Feed export"
        sub={`${ips} IPs and ranges · ${s.exported.domain ?? 0} domains · ${s.exported.url ?? 0} URLs published now. Only enforced, unexpired blocks are published, after a second never-block check.`}
      />
      {made && (
        <div className="mb-5 rounded-card border border-warn/40 bg-warn/[0.06] p-4" aria-live="polite">
          <p className="mb-2 flex items-center gap-2 text-[13.5px] font-semibold text-warn">
            <KeyRound className="h-4 w-4" /> Token for {made.name}: copy it now, it is shown once
          </p>
          <p className="flex flex-wrap items-center gap-2 font-mono text-[13px]">
            <span className="select-all break-all">{made.token}</span> <CopyButton value={made.token} />
          </p>
          <ul className="mt-3 space-y-1 font-mono text-[12px] text-ink-muted">
            {made.urls.map((u) => (
              <li key={u} className="select-all break-all">
                {u}
              </li>
            ))}
          </ul>
        </div>
      )}
      <ul className="mb-5 space-y-1.5">
        {s.formats.map((f) => (
          <li key={f} className="text-[12.5px]">
            <span className="font-mono text-ink-muted">{s.base}/feeds/&lt;token&gt;/{f}</span>
            <span className="block text-ink-faint">{FORMAT_HINT[f] ?? ""}</span>
          </li>
        ))}
      </ul>
      <h3 className="mb-2 text-[13.5px] font-semibold">Tokens</h3>
      {s.tokens.length ? (
        <ul className="mb-4 divide-y divide-line/70 rounded-ctl border border-line">
          {s.tokens.map((t) => (
            <li
              key={t.id}
              className={`flex items-center gap-3 px-3 py-2.5 text-[13px] ${t.revokedAt ? "opacity-50" : ""}`}
            >
              <span className="min-w-0 flex-1">
                <b>{t.name}</b> <span className="font-mono text-ink-faint">{t.prefix}…</span>
                <span className="block text-[12px] text-ink-faint">
                  made by {t.createdBy} {ago(t.createdAt)} · last pull {ago(t.lastUsedAt)}
                  {t.revokedAt && ` · revoked ${ago(t.revokedAt)}`}
                </span>
              </span>
              {!t.revokedAt && s.canEdit && (
                <button
                  className="btn-ghost h-8 text-[12.5px] hover:!text-down"
                  onClick={() => revoke(t.id)}
                  disabled={!!busy}
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mb-4 text-[13px] text-ink-muted">No tokens yet: nothing can pull the feed.</p>
      )}
      {s.canEdit && (
        <form onSubmit={create} className="flex gap-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="ctl flex-1"
            placeholder="New token for, e.g. hq-palo-alto"
            maxLength={64}
            required
          />
          <button className="btn-primary" disabled={busy === "new"}>
            {busy === "new" ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Create token
          </button>
        </form>
      )}
      {error && <p className="mt-2 text-[13px] text-down">{error}</p>}
    </Card>
  );
}

function NeverBlockCard() {
  const { data, error, reload } = useApi<Never>("neverblock");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string>();
  if (error && !data) return <Card><Failed error={error} onRetry={reload} /></Card>;
  if (!data) return <Card><Skeleton className="h-40" /></Card>;
  const add = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setMsg(undefined);
    try {
      await post("neverblock", { value, reason });
      setValue("");
      setReason("");
      reload();
    } catch (err) {
      setMsg((err as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHead
        title="Never block"
        sub="Checked on every block and every export. Indicators on these stay visible and labelled, so a compromise of your own host is still noticed."
      />
      <div className="mb-4 grid gap-3 text-[12.5px] sm:grid-cols-3">
        <div className="rounded-ctl border border-line bg-card-2/40 p-3">
          <p className="text-ink-faint">Your assets</p>
          <p className="text-[18px] font-bold">{Object.values(data.assets).reduce((a, b) => a + b, 0)}</p>
        </div>
        <div className="rounded-ctl border border-line bg-card-2/40 p-3">
          <p className="text-ink-faint">From your org profile</p>
          <p className="text-[18px] font-bold">{data.own.length}</p>
        </div>
        <div className="rounded-ctl border border-line bg-card-2/40 p-3">
          <p className="text-ink-faint">Public DNS resolvers</p>
          <p className="text-[18px] font-bold">{data.resolvers.length}</p>
        </div>
      </div>
      <p className="mb-3 flex items-center gap-2 text-[12.5px] text-ink-muted">
        <ShieldCheck className="h-4 w-4 text-up" /> Private, loopback, link-local and documentation ranges are always protected.
      </p>
      {data.manual.length > 0 && (
        <ul className="mb-4 divide-y divide-line/70 rounded-ctl border border-line">
          {data.manual.map((m) => (
            <li key={m.id} className="flex items-center gap-3 px-3 py-2.5 text-[13px]">
              <Ioc value={m.value} className="text-[13px]" />
              <span className="min-w-0 flex-1 truncate text-ink-muted">{m.reason}</span>
              {data.canEdit && (
                <button
                  className="btn-ghost h-8 w-8 !px-0 hover:!text-down"
                  aria-label={`Remove ${m.value}`}
                  onClick={async () => {
                    await send("DELETE", `/app/api/neverblock/${m.id}`);
                    reload();
                  }}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      {data.canEdit && (
        <form onSubmit={add} className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
          <input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            className="ctl font-mono"
            placeholder="IP, CIDR range or domain"
            required
          />
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="ctl"
            placeholder="Why it is ours"
            minLength={3}
            required
          />
          <button className="btn-primary" disabled={busy}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add
          </button>
        </form>
      )}
      {msg && <p className="mt-2 text-[13px] text-down">{msg}</p>}
    </Card>
  );
}

// ── Main Settings Component ──────────────────────────────────────────────────

export default function Settings({ initialTab }: { initialTab?: Tab }) {
  usePage("Platform", "Settings");
  const [searchParams, setSearchParams] = useSearchParams();
  const currentTab = (searchParams.get("tab") as Tab) || initialTab || "users";

  const { data: me } = useApi<Me>("me");
  const { data: policyData, error: policyError, reload: reloadPolicy } = useApi<SettingsData>("settings");

  const setTab = (t: Tab) => {
    setSearchParams({ tab: t });
  };

  return (
    <div className="mx-auto w-full max-w-[1320px] space-y-6 px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-line pb-4">
        <button
          onClick={() => setTab("users")}
          className={`flex items-center gap-2 rounded-ctl px-4 py-2 text-[14px] font-medium transition-colors ${
            currentTab === "users"
              ? "bg-accent text-on-accent shadow-glow"
              : "text-ink-muted hover:bg-card-2 hover:text-ink"
          }`}
        >
          <Users className="h-4 w-4" /> Team & Users
        </button>

        <button
          onClick={() => setTab("security")}
          className={`flex items-center gap-2 rounded-ctl px-4 py-2 text-[14px] font-medium transition-colors ${
            currentTab === "security"
              ? "bg-accent text-on-accent shadow-glow"
              : "text-ink-muted hover:bg-card-2 hover:text-ink"
          }`}
        >
          <KeyRound className="h-4 w-4" /> Two-Factor & SSO
        </button>

        <button
          onClick={() => setTab("audit")}
          className={`flex items-center gap-2 rounded-ctl px-4 py-2 text-[14px] font-medium transition-colors ${
            currentTab === "audit"
              ? "bg-accent text-on-accent shadow-glow"
              : "text-ink-muted hover:bg-card-2 hover:text-ink"
          }`}
        >
          <History className="h-4 w-4" /> Audit Log
        </button>

        <button
          onClick={() => setTab("policy")}
          className={`flex items-center gap-2 rounded-ctl px-4 py-2 text-[14px] font-medium transition-colors ${
            currentTab === "policy"
              ? "bg-accent text-on-accent shadow-glow"
              : "text-ink-muted hover:bg-card-2 hover:text-ink"
          }`}
        >
          <Sliders className="h-4 w-4" /> Policy & Feeds
        </button>
      </div>

      {/* Tab Panels */}
      {currentTab === "users" && <TeamSection me={me} />}

      {currentTab === "security" && <SecuritySection me={me} />}

      {currentTab === "audit" && <AuditLogSection />}

      {currentTab === "policy" && (
        <div className="space-y-6">
          {policyError && !policyData ? (
            <Card>
              <Failed error={policyError} onRetry={reloadPolicy} />
            </Card>
          ) : !policyData ? (
            <Skeleton className="h-80" />
          ) : (
            <>
              <div className="grid gap-6 xl:grid-cols-2">
                <PolicyCard s={policyData} reload={reloadPolicy} />
                <ExportCard s={policyData} reload={reloadPolicy} />
              </div>
              <NeverBlockCard />
            </>
          )}
        </div>
      )}
    </div>
  );
}
