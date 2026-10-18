import { Eye, Maximize2, Minus, Plus, ShieldBan } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type PointerEvent, type WheelEvent } from "react";
import { Link } from "react-router-dom";
import { useApi } from "../lib/api";
import { ago } from "../lib/format";
import { Ioc, VerdictPill } from "./intel";
import { Empty, Failed, Skeleton } from "./states";
import { Card, CardHead, Segmented, useToken } from "./ui";

interface MapIp {
  id: number;
  value: string;
  verdict: string;
  score: number | null;
  blocked: string | null;
  flagged: boolean;
  seen: number;
  asn: string;
  lastSeen: string | null;
}

interface MapPoint {
  lat: number;
  lon: number;
  x: number;
  y: number;
  place: string;
  country: string;
  count: number;
  tone: "malicious" | "suspicious" | "unknown";
  acted: number;
  seen: number;
  ips: MapIp[];
}

interface MapData {
  mode: string;
  points: MapPoint[];
  located: number;
  missing: number;
  truncated: boolean;
}

const MODES = ["Feed landscape", "Blocked & flagged"] as const;
const ONLY = ["All", "Blocked/flagged", "Seen"] as const;
const ORDER = ["Latest", "Score"] as const;
type Mode = (typeof MODES)[number];
const W = 1000;
const H = 500;
const MAX_K = 12;
const TONE: Record<string, string> = { malicious: "down", suspicious: "warn", unknown: "ink-muted" };

interface View {
  k: number;
  x: number;
  y: number;
}

function clampView(v: View): View {
  const k = Math.min(MAX_K, Math.max(1, v.k));
  const w = W / k;
  const h = H / k;
  return { k, x: Math.min(W - w, Math.max(0, v.x)), y: Math.min(H - h, Math.max(0, v.y)) };
}

/** World map of located indicator IPs: scroll or +/− to zoom, drag to pan,
 * hover a dot to list every IP there (click it to keep the list open). */
export default function ThreatMap() {
  const token = useToken();
  const [mode, setMode] = useState<Mode>("Feed landscape");
  const { data, error, reload } = useApi<MapData>("threatmap", { mode: mode === "Feed landscape" ? "landscape" : "acted" });
  const [land, setLand] = useState<string>();
  const [view, setView] = useState<View>({ k: 1, x: 0, y: 0 });
  const [hover, setHover] = useState<MapPoint>();
  const [pinned, setPinned] = useState<MapPoint>();
  const [filter, setFilter] = useState("");
  const [only, setOnly] = useState<(typeof ONLY)[number]>("All");
  const [order, setOrder] = useState<(typeof ORDER)[number]>("Latest");
  const svg = useRef<SVGSVGElement>(null);
  const drag = useRef<{ px: number; py: number; v: View; moved: boolean } | null>(null);

  useEffect(() => {
    fetch("/app/maps/world_land.path")
      .then((r) => (r.ok ? r.text() : Promise.reject(new Error(String(r.status)))))
      .then(setLand)
      .catch(() => setLand(""));
  }, []);
  useEffect(() => {
    setPinned(undefined);
    setHover(undefined);
  }, [mode]);

  const toCanvas = (clientX: number, clientY: number) => {
    const r = svg.current!.getBoundingClientRect();
    return { x: view.x + ((clientX - r.left) / r.width) * (W / view.k), y: view.y + ((clientY - r.top) / r.height) * (H / view.k) };
  };
  const zoomAt = (factor: number, cx = view.x + W / view.k / 2, cy = view.y + H / view.k / 2) => {
    const k = Math.min(MAX_K, Math.max(1, view.k * factor));
    const f = view.k / k;
    setView(clampView({ k, x: cx - (cx - view.x) * f, y: cy - (cy - view.y) * f }));
  };
  const onWheel = (e: WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const c = toCanvas(e.clientX, e.clientY);
    zoomAt(e.deltaY < 0 ? 1.35 : 1 / 1.35, c.x, c.y);
  };
  const onDown = (e: PointerEvent<SVGSVGElement>) => {
    drag.current = { px: e.clientX, py: e.clientY, v: view, moved: false };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  };
  const onMove = (e: PointerEvent<SVGSVGElement>) => {
    const d = drag.current;
    if (!d) return;
    const r = svg.current!.getBoundingClientRect();
    const dx = ((e.clientX - d.px) / r.width) * (W / d.v.k);
    const dy = ((e.clientY - d.py) / r.height) * (H / d.v.k);
    if (Math.abs(e.clientX - d.px) + Math.abs(e.clientY - d.py) > 3) d.moved = true;
    setView(clampView({ k: d.v.k, x: d.v.x - dx, y: d.v.y - dy }));
  };
  const onUp = () => {
    drag.current = null;
  };

  // svg wheel listeners are passive in React; attach a non-passive one so the page doesn't scroll
  useEffect(() => {
    const el = svg.current;
    if (!el) return;
    const stop = (e: globalThis.WheelEvent) => e.preventDefault();
    el.addEventListener("wheel", stop, { passive: false });
    return () => el.removeEventListener("wheel", stop);
  }, [data]);

  const rows = useMemo(() => {
    const all = (data?.points ?? []).flatMap((p) => p.ips.map((ip) => ({ ...ip, place: p.place, country: p.country })));
    const f = filter.trim().toLowerCase();
    return all
      .filter((r) => (only === "Blocked/flagged" ? r.blocked || r.flagged : only === "Seen" ? r.seen > 0 : true))
      .filter((r) => !f || r.value.toLowerCase().includes(f) || r.place.toLowerCase().includes(f) || r.asn.toLowerCase().includes(f))
      .sort((a, b) => (order === "Score" ? (b.score ?? 0) - (a.score ?? 0) : (b.lastSeen ?? "").localeCompare(a.lastSeen ?? "")));
  }, [data, filter, only, order]);

  const shown = pinned ?? hover;
  const max = Math.max(1, ...(data?.points ?? []).map((p) => p.count));
  const acted = (data?.points ?? []).reduce((n, p) => n + p.acted, 0);
  const seen = (data?.points ?? []).reduce((n, p) => n + p.seen, 0);

  return (
    <Card className="!p-0">
      <div className="p-5 pb-3 sm:p-6 sm:pb-3">
        <CardHead
          title="Threat map"
          sub={data ? `${data.located.toLocaleString()} located IPs · ${acted.toLocaleString()} blocked or flagged · ${seen.toLocaleString()} seen in our alerts${data.missing ? ` · ${data.missing.toLocaleString()} without a location yet` : ""}` : "Where the infrastructure behind your indicators is"}
        >
          <Segmented value={mode} options={MODES} onChange={setMode} label="Which IPs" />
        </CardHead>
      </div>
      {error && !data ? (
        <Failed error={error} onRetry={reload} />
      ) : !data || land === undefined ? (
        <Skeleton className="mx-6 mb-6 h-[380px]" />
      ) : (
        <div className="grid gap-4 px-5 pb-5 sm:px-6 sm:pb-6 xl:grid-cols-[minmax(0,1fr)_380px]">
          <div>
            <div className="relative overflow-hidden rounded-card border border-line bg-bg">
              <svg
                ref={svg}
                viewBox={`${view.x} ${view.y} ${W / view.k} ${H / view.k}`}
                className="block h-auto w-full touch-none select-none"
                style={{ cursor: drag.current ? "grabbing" : "grab" }}
                role="img"
                aria-label={`Map of ${data.points.length} locations`}
                onWheel={onWheel}
                onPointerDown={onDown}
                onPointerMove={onMove}
                onPointerUp={onUp}
                onPointerLeave={onUp}
                onClick={(e) => {
                  if (e.target === svg.current) setPinned(undefined);
                }}
              >
                {land ? <path d={land} fill={token("card-2")} stroke={token("line")} strokeWidth={0.6 / view.k} /> : null}
                {data.points.map((p) => {
                  const r = (3 + 9 * Math.sqrt(p.count / max)) / Math.sqrt(view.k);
                  const color = TONE[p.tone] ?? "ink-muted";
                  const active = shown === p;
                  return (
                    <g
                      key={`${p.x},${p.y}`}
                      className="cursor-pointer"
                      onMouseEnter={() => setHover(p)}
                      onMouseLeave={() => setHover(undefined)}
                      onClick={(e) => {
                        e.stopPropagation();
                        if (!drag.current?.moved) setPinned(pinned === p ? undefined : p);
                      }}
                    >
                      <circle cx={p.x} cy={p.y} r={r * 2.2} fill={token(color, active ? 0.3 : 0.14)} />
                      {p.seen > 0 && <circle cx={p.x} cy={p.y} r={r * 1.55} fill="none" stroke={token("info-soft")} strokeWidth={1.4 / Math.sqrt(view.k)} />}
                      {p.acted > 0 && <circle cx={p.x} cy={p.y} r={r * 1.3} fill="none" stroke={token("down")} strokeWidth={1.4 / Math.sqrt(view.k)} />}
                      <circle cx={p.x} cy={p.y} r={r} fill={token(color, 0.9)} stroke={token("card")} strokeWidth={1 / Math.sqrt(view.k)} />
                      {view.k >= 3 && (
                        <text x={p.x + r + 2 / view.k} y={p.y + 3 / view.k} fontSize={10 / view.k} fill={token("ink-muted")}>
                          {p.place} · {p.count}
                        </text>
                      )}
                    </g>
                  );
                })}
              </svg>
              <div className="absolute right-2 top-2 flex flex-col gap-1">
                <button className="btn-ghost h-8 w-8 !px-0" onClick={() => zoomAt(1.6)} aria-label="Zoom in">
                  <Plus className="h-4 w-4" />
                </button>
                <button className="btn-ghost h-8 w-8 !px-0" onClick={() => zoomAt(1 / 1.6)} aria-label="Zoom out">
                  <Minus className="h-4 w-4" />
                </button>
                <button className="btn-ghost h-8 w-8 !px-0" onClick={() => setView({ k: 1, x: 0, y: 0 })} aria-label="Reset the view">
                  <Maximize2 className="h-4 w-4" />
                </button>
              </div>
              {shown && (
                <div className="absolute bottom-2 left-2 max-h-[70%] w-[min(340px,calc(100%-1rem))] overflow-y-auto rounded-ctl border border-line bg-card-2/95 p-3 text-[12.5px] shadow-xl">
                  <p className="font-semibold">
                    {shown.place} <span className="font-normal text-ink-muted">· {shown.count} IP{shown.count === 1 ? "" : "s"}</span>
                    {pinned && <span className="ml-1 text-ink-faint">(pinned; click the map to close)</span>}
                  </p>
                  <ul className="mt-2 space-y-1">
                    {shown.ips.map((ip) => (
                      <li key={ip.id} className="flex items-center justify-between gap-2">
                        <Link to={`/indicators/${ip.id}`} className="truncate font-mono hover:text-accent-soft">
                          <Ioc value={ip.value} />
                        </Link>
                        <span className="flex shrink-0 items-center gap-1.5">
                          {ip.seen > 0 && <Eye className="h-3.5 w-3.5 text-info-soft" aria-label="seen in our alerts" />}
                          {(ip.blocked || ip.flagged) && <ShieldBan className="h-3.5 w-3.5 text-down" aria-label={ip.blocked ? `blocked (${ip.blocked})` : "flagged"} />}
                          <span className={`tabular-nums text-${TONE[ip.verdict] ?? "ink-muted"}`}>{ip.score != null ? Math.round(ip.score) : "–"}</span>
                        </span>
                      </li>
                    ))}
                  </ul>
                  {shown.count > shown.ips.length && <p className="mt-1 text-ink-faint">and {shown.count - shown.ips.length} more</p>}
                </div>
              )}
            </div>
            <p className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-ink-faint">
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-down" /> malicious</span>
              <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full bg-warn" /> suspicious</span>
              <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full ring-2 ring-info-soft" /> seen in our alerts</span>
              <span className="inline-flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full ring-2 ring-down" /> blocked or flagged</span>
              <span>Scroll or +/− to zoom, drag to pan, hover a dot to list its IPs.</span>
            </p>
          </div>
          <div className="relative min-h-[320px]">
          <div className="flex flex-col rounded-card border border-line xl:absolute xl:inset-0">
            <div className="space-y-2 border-b border-line p-3">
              <p className="label">Located IPs <span className="text-ink-faint">{rows.length.toLocaleString()}</span></p>
              <input value={filter} onChange={(e) => setFilter(e.target.value)} className="ctl h-8 w-full text-[13px]" placeholder="Filter by IP, city, country or network…" />
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Segmented value={only} options={ONLY} onChange={setOnly} label="Which IPs" />
                <Segmented value={order} options={ORDER} onChange={setOrder} label="Order" />
              </div>
            </div>
            {!rows.length ? (
              <Empty>{data.located ? "Nothing matches." : "No located IPs yet: locations come from RIPEstat lookups of IP indicators."}</Empty>
            ) : (
              <ul className="max-h-[420px] min-h-0 flex-1 divide-y divide-line/70 overflow-y-auto xl:max-h-none">
                {rows.slice(0, 300).map((r) => (
                  <li key={r.id}>
                    <Link to={`/indicators/${r.id}`} className="flex items-center gap-3 px-3 py-2 hover:bg-row-hover">
                      <span className="w-8 shrink-0 rounded bg-chip px-1 text-center text-[11px] font-semibold text-chip-ink ring-1 ring-line">{(r.country || "?").slice(0, 2).toUpperCase()}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-mono text-[13px]"><Ioc value={r.value} /></span>
                        <span className="block truncate text-[11.5px] text-ink-faint">
                          {r.place}
                          {r.asn ? ` · ${r.asn}` : ""}
                          {r.blocked ? ` · blocked (${r.blocked})` : r.flagged ? " · flagged" : ""}
                          {r.seen ? ` · seen ${r.seen}×` : ""} · {ago(r.lastSeen)}
                        </span>
                      </span>
                      <VerdictPill verdict={r.verdict} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </div>
          </div>
        </div>
      )}
    </Card>
  );
}
