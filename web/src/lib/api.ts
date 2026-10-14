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
