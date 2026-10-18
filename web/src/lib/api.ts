import { useCallback, useEffect, useRef, useState } from "react";
import { live } from "./ioc";

/* Everything the app reads comes from /app/api with the session cookie.
 * A 401 means the session ended: go to the sign-in page and come back. */

export type Params = Record<string, string | number | undefined>;

/** The session ended: go to the sign-in page, then come back here. */
export function toLogin(): void {
  const here = window.location.pathname + window.location.search;
  window.location.assign(`/app/login?next=${encodeURIComponent(here)}`);
}

export async function signOut(): Promise<void> {
  await fetch("/app/api/session", { method: "DELETE", credentials: "same-origin" }).catch(() => undefined);
  window.location.assign("/app/login");
}

export async function get<T>(path: string, params: Params = {}): Promise<T> {
  const url = new URL(`/app/api/${path}`, window.location.origin);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
  const r = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (r.status === 401) {
    toLogin();
    throw new Error("signed out");
  }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText || "error"}`);
  return live(await r.json()) as T;
}

export interface Loaded<T> {
  data?: T; // the last good answer stays while a new one loads (no flicker on toggles)
  error?: string;
  loading: boolean;
  reload: () => void;
}

export function useApi<T>(path: string, params: Params = {}): Loaded<T> {
  const key = `${path}?${JSON.stringify(params)}`;
  const [state, setState] = useState<{ data?: T; error?: string; loading: boolean }>({ loading: true });
  const [tick, setTick] = useState(0);
  const latest = useRef(key);
  useEffect(() => {
    latest.current = key;
    setState((s) => ({ ...s, loading: true, error: undefined }));
    get<T>(path, params)
      .then((data) => latest.current === key && setState({ data, loading: false }))
      .catch((e: Error) => latest.current === key && setState((s) => ({ ...s, error: e.message, loading: false })));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { ...state, reload };
}

/** The value after it has stopped changing for `ms` (search boxes). */
export function useDebounced<T>(value: T, ms = 250): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

// ── shapes served by /app/api (threatlens/webapp.py) ─────────────────────────

export interface Me {
  id?: number;
  name: string;
  login?: string;
  role: "admin" | "analyst" | "viewer";
  clearance: string;
  initials: string;
  totp_enabled?: boolean;
}

export interface Kpi {
  key: string;
  label: string;
  value: number;
  of?: number;
  change: number | null;
  hint: string;
  icon: "radar" | "alert" | "server" | "feed";
}

export type Range = "Year" | "Month" | "Week" | "Day";

export interface Point {
  label: string;
  date: string;
  malicious: number;
  suspicious: number;
}

export interface Activity {
  range: Range;
  total: number;
  change: number | null;
  points: Point[];
}

export interface Types {
  scope: string;
  scopes: string[];
  total: number;
  items: { type: string; name: string; value: number }[];
}

export interface Collection {
  week: string;
  weeks: string[];
  total: number;
  days: { day: string; ok: number; other: number }[];
}

export type Family = "ip" | "domain" | "url" | "hash" | "cve" | "email" | "file" | "registry" | "other";

export interface IndicatorRow {
  id: number;
  value: string;
  type: Family;
  typeLabel: string;
  sources: string[];
  firstSeen: string;
  lastSeen: string | null;
  country: string | null;
  status: "active" | "expired" | "false_positive" | "revoked" | "new";
  score: number | null;
  tlp: string;
}

export interface Page<T> {
  total: number;
  page: number;
  size: number;
  items: T[];
}

/** POST JSON to /app/api; the browser marks it same-origin, which the API requires for changes. */
export async function post<T>(path: string, body: unknown = {}): Promise<T> {
  const r = await fetch(`/app/api/${path}`, {
    method: "POST",
    credentials: "same-origin",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (r.status === 401) {
    toLogin();
    throw new Error("signed out");
  }
  const data = live(await r.json().catch(() => ({})));
  if (!r.ok) {
    const detail = (data as { detail?: unknown }).detail;
    throw new Error(typeof detail === "string" ? detail : Array.isArray(detail) ? "Check the form: some values aren't valid" : `${r.status} error`);
  }
  return data as T;
}

// ── attack surface (ReconX engine, via /app/api/recon) ───────────────────────

export interface EngineStatus {
  configured: boolean;
  reachable: boolean;
  browser?: boolean;
  nmap?: boolean;
}

export interface ScanRow {
  file?: string;
  job_id?: string;
  target: string;
  timestamp: string;
  mode: "passive" | "active" | "both";
  has_passive: boolean;
  has_active: boolean;
  subdomains: number;
  live_hosts: number;
  findings: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  imported: boolean;
}

export interface ProgressEvent {
  step: string;
  message: string;
  percent: number;
  level: "info" | "warn" | "done" | "error";
}

export interface JobStatus {
  id: string;
  status: "running" | "done" | "error";
  events: ProgressEvent[];
  file?: string;
  error?: string;
}

export interface HostNode {
  hostname: string;
  sources: string[];
  confidence: number;
  is_alive: boolean;
  resolved_ips?: string[];
  asn?: string;
  organization?: string;
  isp?: string;
  cloud_provider?: string;
  country?: string;
}

export interface Finding {
  category: string;
  severity: string;
  title: string;
  description: string;
  evidence?: string;
  target: string;
}

export interface Port {
  port: number;
  protocol: string;
  state: string;
  service?: string;
  banner?: string;
}

export interface SourceRun {
  name: string;
  purpose: string;
  status: string;
  error?: string;
  duration_ms: number;
  results: number;
  reliability: string;
}

export interface Report {
  target?: { value: string; type: string };
  timestamp: string;
  normalized_assets?: { asset: string; type: string; sources: string[] }[];
  attack_surface_graph?: { target_domain: string; total_assets: number; live_assets: number; nodes: HostNode[] };
  passive_intel?: { sources?: SourceRun[]; ips?: { ip: string }[]; certificates?: unknown[] };
  active_recon?: { findings?: Finding[]; open_ports?: Port[]; tech_stack?: unknown };
  web_map?: { total_pages_crawled?: number };
}

export interface GeoPoint {
  lat: number;
  lon: number;
  x: number;
  y: number;
  place: string;
  country?: string;
  ips: string[];
  hosts: number;
  providers?: string[];
  exposed?: number;
}

export interface ChangeSet {
  previous_scan: string;
  previous_file?: string;
  summary: Record<string, number>;
  events?: { category: string; action: "added" | "removed" | "changed"; key: string; old?: string; new?: string }[];
}

export interface Monitor {
  id: string;
  target: string;
  every: string;
  enabled: boolean;
  webhook: string;
  webhook_kind?: string;
  min_severity?: string;
  last_run?: string;
  next_run: string;
  last_status?: string;
  last_error?: string;
  last_file?: string;
  last_alerts: number;
  runs: number;
}

export interface Alert {
  id: string;
  target: string;
  time: string;
  rule: string;
  severity: string;
  title: string;
  items?: string[];
  more?: number;
  scan_file?: string;
}

/** A plain-text resource (the map's land outline), fetched once. */
export function useText(path: string): string | undefined {
  const [text, setText] = useState<string>();
  useEffect(() => {
    let live = true;
    fetch(`/app/api/${path}`, { credentials: "same-origin" })
      .then((r) => (r.ok ? r.text() : undefined))
      .then((t) => live && setText(t))
      .catch(() => undefined);
    return () => {
      live = false;
    };
  }, [path]);
  return text;
}

/** Send a request with any method and JSON body to any same-origin API path. */
export async function send<T>(method: "POST" | "PUT" | "PATCH" | "DELETE", url: string, body?: unknown): Promise<T> {
  const r = await fetch(url, {
    method,
    credentials: "same-origin",
    headers: { Accept: "application/json", ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  if (r.status === 401) {
    toLogin();
    throw new Error("signed out");
  }
  const data = live(await r.json().catch(() => ({})));
  if (!r.ok) {
    const detail = (data as { detail?: unknown }).detail;
    const msg =
      typeof detail === "string" ? detail : Array.isArray(detail) ? ((detail[0] as { msg?: string })?.msg ?? "invalid input") : `${r.status} error`;
    throw new Error(msg);
  }
  return data as T;
}

/** GET from /api/v1 (the REST API, with the session) as a hook. */
export function useV1<T>(path: string, params: Params = {}): Loaded<T> {
  return useApi<T>(`../../api/v1/${path}`, params);
}

/** Read newline-delimited JSON events from a streaming response. */
export async function readEvents<T>(r: Response, onEvent: (e: T) => void): Promise<void> {
  if (!r.ok || !r.body) {
    const data = live(await r.json().catch(() => ({})));
    const detail = (data as { detail?: unknown }).detail;
    throw new Error(typeof detail === "string" ? detail : `${r.status} error`);
  }
  const reader = r.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    let i = buf.indexOf("\n");
    while (i >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) onEvent(live(JSON.parse(line)) as T);
      i = buf.indexOf("\n");
    }
  }
  if (buf.trim()) onEvent(live(JSON.parse(buf)) as T);
}

// ── threat intel shapes (/api/v1 and /app/api) ───────────────────────────────

export interface Indicator {
  id: number;
  type: string;
  value: string;
  defanged: string;
  status: string;
  confidence: number;
  tlp: string;
  labels: string[];
  first_seen: string;
  last_seen: string;
  sources: string[];
  priority_score: number | null;
  verdict: string | null;
  valid_until: string | null;
  analyst_verdict: string | null;
}

export interface Signal {
  source: string;
  upstream: string;
  kind: string;
  confidence: number;
  weight: number;
  decay: number;
  age_days: number;
  value: number;
  text: string;
  counted: boolean;
}

export interface IndicatorDetail extends Indicator {
  sightings: {
    source: string;
    first_seen: string;
    last_seen: string;
    times_reported: number;
    confidence: number;
    labels: string[];
    context: Record<string, unknown>;
  }[];
  score_breakdown: {
    formula?: string;
    base?: { value: number; source: string | null; kind: string | null };
    corroboration?: { value: number; upstreams: string[] };
    relevance?: { value: number; applied: boolean; hits: { kind: string; points: number; reason: string }[] };
    penalty?: { value: number; items: { kind: string; points: number; reason: string }[] };
    signals?: Signal[];
    suppressed?: string | null;
    half_life_days?: number;
  } | null;
  feedback: { verdict: string; actor: string; note: string; at: string }[];
}

export interface Pivot {
  ref: string;
  label: string;
  id: string | null;
  type: string;
  href: string;
  rel: string;
  source: string | null;
  origin: string;
  via: string | null;
}

export interface IndicatorRelated {
  enrichments: (Card & { fresh: boolean })[];
  groups: { name: string; items: Pivot[]; total: number }[];
  techniques: Pivot[];
  timeline: { at: string | null; kind: "first" | "last" | "enriched"; source: string; times: number }[];
}

export interface SavedSearch {
  id: number;
  name: string;
  query: string;
  created_at: string | null;
}

export interface Card {
  enricher: string;
  title: string;
  status: string;
  mode?: string;
  fetchedAt?: string;
  headline: string;
  tone: "mal" | "sus" | "ok" | "info" | "off";
  rows: [string, string | string[]][];
  evidence: { kind: string; text: string }[];
  error: string | null;
}

export interface Known {
  indicator_id: number;
  status: string;
  confidence: number;
  tlp: string;
  labels: string[];
  sources: string[];
  first_seen: string | null;
  last_seen: string | null;
  analyst_verdict: string | null;
  analyst_verdict_by: string | null;
  priority_score: number | null;
}

export interface Local {
  known: Known | null;
  asset: { kind: string; target: string } | null;
  allowlist: { effect: string | null; reasons: string[]; labels: string[] } | null;
  related: { label: string; ref: string }[];
}

export interface QueryInfo {
  type: string;
  typeLabel: string;
  value: string;
}

export interface Block {
  id: number;
  kind: string;
  value: string;
  state: string;
  mode: "monitor" | "enforce";
  reason: string;
  score: number | null;
  tlp: string;
  note: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  requested_by: string | null;
  approved_by: string | null;
  lifted_by: string | null;
  lifted_at: string | null;
}

export interface VerifyDone extends Local {
  event: "done";
  query: QueryInfo;
  verdict: string;
  verdictLabel: string;
  score: number;
  action: string;
  actionLabel: string;
  actionText: string;
  tlp: string;
  summary: string;
  partial: boolean;
  cards: Card[];
  links: { title: string; url: string }[];
  block: Block | null;
  blockable: boolean;
}

/** A scanned public name that resolves to (or near) an internal address. */
export interface InternalHost {
  name: string;
  target: string;
  assetId: number;
  lastSeen: string;
  ips?: string[];
}

/** Verify on a private or reserved address: answered from our own data only. */
export interface InternalResult {
  event: "internal";
  query: QueryInfo;
  address: string;
  version: 4 | 6;
  range: { network: string; label: string; standard: string; note: string };
  subnet: string;
  publicNames: InternalHost[];
  nearbyNames: InternalHost[];
  cases: { id: number; title: string; status: string; severity: string; tlp: string }[];
}

export type VerifyEvent =
  | ({ event: "start"; query: QueryInfo; pending: { enricher: string; title: string }[] } & Local)
  | { event: "provider"; card: Card }
  | VerifyDone
  | InternalResult
  | { event: "error"; message: string };

export interface BulkRow {
  query: QueryInfo;
  verdict: string;
  verdictLabel: string;
  score: number;
  action: string;
  actionLabel: string;
  tlp: string;
  sources: string[];
  known: boolean;
  analystVerdict: string | null;
  country: string | null;
  signals: { name: string; kind: string; text: string; figure: number | null }[];
  asset: boolean;
  block: { id: number; mode: string; state: string } | null;
  blockable: boolean;
}

export type BulkEvent =
  | { event: "start"; total: number; notes: string[] }
  | { event: "row"; row: BulkRow; done: number; total: number; counts: Record<string, number> }
  | { event: "skip"; done: number; total: number }
  | { event: "done"; total: number; counts: Record<string, number>; calls: number; providers: boolean; blocked: string[]; refused: string[] };

export interface CaseRow {
  id: number;
  title: string;
  status: "open" | "closed";
  severity: "low" | "medium" | "high" | "critical";
  tlp: string;
  summary: string;
  conclusion: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  items: number;
}

export interface CaseItem {
  id: number;
  kind: string;
  ref: string;
  label: string;
  snapshot: Record<string, unknown>;
  note: string;
  tlp: string;
  added_by: string;
  added_at: string;
}

export interface CaseDetail extends CaseRow {
  evidence: CaseItem[];
}

export interface SourceOut {
  name: string;
  title: string;
  kind: string;
  reliability: string;
  reliability_note: string;
  credibility: number;
  weight_factor: number;
  feedback_tp: number;
  feedback_fp: number;
  license: string;
  license_url: string;
  commercial_use: boolean;
  redistribution: boolean;
  attribution: string | null;
  requires_key: boolean;
  key_configured: boolean;
  enabled: boolean;
  health: string;
  interval_minutes: number;
  last_run_at: string | null;
  last_success_at: string | null;
  next_run_at: string | null;
  last_error: string | null;
  custom: boolean;
}

export interface RunOut {
  started_at: string;
  finished_at: string | null;
  status: string;
  http_status: number | null;
  items_total: number;
  items_new: number;
  items_updated: number;
  items_rejected: number;
  items_allowlisted: number;
  error: string | null;
}

export interface AssetOut {
  id: number;
  kind: string;
  value: string;
  target: string;
  origin: string;
  first_seen: string;
  last_seen: string;
  details: Record<string, unknown>;
  products: string[];
  indicator: { indicator_id: number; status: string; priority_score: number | null; sources: string[] } | null;
}

// ── team and security (ADR 0017) ─────────────────────────────────────────────

export interface UserItem {
  id: number;
  name: string;
  login: string;
  role: "admin" | "analyst" | "viewer";
  tlpClearance: string | null;
  createdAt: string;
  lastLoginAt: string | null;
  disabledAt: string | null;
  totpEnabled: boolean;
  ssoProvider: string | null;
}

export interface TwoFactorStatus {
  enabled: boolean;
  enabledAt: string | null;
}

export interface TwoFactorSetupData {
  secret: string;
  otpauth_url: string;
  qr_svg: string;
}

export interface SsoProvider {
  id: string;
  name: string;
}

export interface SsoConfig {
  enabled: boolean;
  default_role: "admin" | "analyst" | "viewer";
  auto_provision: boolean;
  providers: {
    google?: { enabled?: boolean; client_id?: string; client_secret?: string; hosted_domain?: string };
    microsoft?: { enabled?: boolean; client_id?: string; client_secret?: string; tenant?: string };
    okta?: { enabled?: boolean; client_id?: string; client_secret?: string; domain?: string };
  };
}

export interface AuditItem {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  details: Record<string, unknown>;
}

export interface AuditCategory {
  id: string;
  label: string;
  count: number;
}

export interface AuditResponse {
  total: number;
  items: AuditItem[];
  actors: string[];
  categories: AuditCategory[];
}

