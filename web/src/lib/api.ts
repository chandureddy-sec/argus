import { useCallback, useEffect, useRef, useState } from "react";

/* Everything the app reads comes from /app/api with the session cookie.
 * A 401 means the session ended: go to the sign-in page and come back. */

export type Params = Record<string, string | number | undefined>;

export async function get<T>(path: string, params: Params = {}): Promise<T> {
  const url = new URL(`/app/api/${path}`, window.location.origin);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
  const r = await fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } });
  if (r.status === 401) {
    window.location.assign("/ui/login?next=/app/");
    throw new Error("signed out");
  }
  if (!r.ok) throw new Error(`${r.status} ${r.statusText || "error"}`);
  return (await r.json()) as T;
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
  name: string;
  role: "admin" | "analyst" | "viewer";
  clearance: string;
  initials: string;
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
    window.location.assign("/ui/login?next=/app/");
    throw new Error("signed out");
  }
  const data = await r.json().catch(() => ({}));
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
