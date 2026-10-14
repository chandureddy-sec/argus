import { Maximize2, Minus, Plus } from "lucide-react";
import { useEffect, useMemo, useRef, useState, type PointerEvent, type WheelEvent } from "react";
import { useApi } from "../lib/api";
import { Empty, Failed, Skeleton } from "./states";
import { token } from "./ui";

interface GNode {
  id: string;
  kind: "domain" | "host" | "cname" | "ip" | "asn" | "provider" | "ns" | "mx";
  label: string;
  detail?: string;
  flags?: string[];
  weight: number;
}

interface GEdge {
  from: string;
  to: string;
  rel: string;
  evidence: "observed" | "enriched" | "inferred";
}

interface Graph {
  target: string;
  nodes: GNode[];
  edges: GEdge[];
  truncated?: boolean;
  omitted_hosts?: number;
}

// Colour per kind, from the design tokens; the scanned domain is the accent.
const KIND: Record<GNode["kind"], { label: string; color: string; ring: number }> = {
  domain: { label: "Domain", color: "accent", ring: 0 },
  host: { label: "Host", color: "accent-soft", ring: 1 },
  cname: { label: "CNAME target", color: "accent-muted", ring: 1 },
  ns: { label: "Name server", color: "ink-muted", ring: 1 },
  mx: { label: "Mail server", color: "ink-muted", ring: 1 },
  ip: { label: "IP address", color: "up", ring: 2 },
  asn: { label: "Network (ASN)", color: "warn", ring: 3 },
  provider: { label: "Provider", color: "down", ring: 3 },
};

interface P {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

/** Fruchterman–Reingold style layout: deterministic start (rings by kind), a fixed number of steps. */
function layout(g: Graph): Map<string, P> {
  const n = g.nodes.length;
  const pos = new Map<string, P>();
  const perRing = new Map<number, number>();
  const seen = new Map<number, number>();
  for (const v of g.nodes) perRing.set(KIND[v.kind]?.ring ?? 2, (perRing.get(KIND[v.kind]?.ring ?? 2) ?? 0) + 1);
  for (const v of g.nodes) {
    const ring = KIND[v.kind]?.ring ?? 2;
    const i = seen.get(ring) ?? 0;
    seen.set(ring, i + 1);
    const a = (2 * Math.PI * i) / Math.max(1, perRing.get(ring) ?? 1) + ring * 0.6;
    const r = ring * 160;
    pos.set(v.id, { x: Math.cos(a) * r, y: Math.sin(a) * r, vx: 0, vy: 0 });
  }
  const k = Math.max(38, 900 / Math.sqrt(Math.max(1, n)));
  const steps = n > 250 ? 120 : 220;
  const list = g.nodes.map((v) => pos.get(v.id)!);
  for (let step = 0; step < steps; step++) {
    const temp = 40 * (1 - step / steps) + 1;
    for (const p of list) {
      p.vx = 0;
      p.vy = 0;
    }
    for (let i = 0; i < list.length; i++) {
      const a = list[i];
      for (let j = i + 1; j < list.length; j++) {
        const b = list[j];
        let dx = a.x - b.x;
        let dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) {
          dx = 0.1 * (i - j);
          dy = 0.1;
          d2 = dx * dx + dy * dy;
        }
        const f = (k * k) / d2;
        a.vx += dx * f;
        a.vy += dy * f;
        b.vx -= dx * f;
        b.vy -= dy * f;
      }
    }
    for (const e of g.edges) {
      const a = pos.get(e.from);
      const b = pos.get(e.to);
      if (!a || !b) continue;
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const f = d / k;
      a.vx -= dx * f;
      a.vy -= dy * f;
      b.vx += dx * f;
      b.vy += dy * f;
    }
    for (const p of list) {
      const d = Math.sqrt(p.vx * p.vx + p.vy * p.vy) || 1;
      p.x += (p.vx / d) * Math.min(d, temp) - p.x * 0.004; // a light pull to the centre
      p.y += (p.vy / d) * Math.min(d, temp) - p.y * 0.004;
    }
  }
  return pos;
}

export default function InfraGraph({ refId }: { refId: string }) {
  const [historical, setHistorical] = useState(false);
  const { data, error, reload, loading } = useApi<Graph>("recon/report/graph", { ref: refId, historical: historical ? "true" : undefined });
  const pos = useMemo(() => (data ? layout(data) : new Map<string, P>()), [data]);
  const [view, setView] = useState({ x: 0, y: 0, s: 1 });
  const [hover, setHover] = useState<GNode>();
  const [focus, setFocus] = useState<string>();
  const drag = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const svg = useRef<SVGSVGElement>(null);

  // Fit the drawing into the box whenever a new graph arrives.
  const bounds = useMemo(() => {
    const xs = [...pos.values()].map((p) => p.x);
    const ys = [...pos.values()].map((p) => p.y);
    if (!xs.length) return { minX: -100, minY: -100, w: 200, h: 200 };
    const minX = Math.min(...xs) - 60;
    const minY = Math.min(...ys) - 60;
    return { minX, minY, w: Math.max(...xs) + 60 - minX, h: Math.max(...ys) + 60 - minY };
  }, [pos]);
  useEffect(() => setView({ x: 0, y: 0, s: 1 }), [bounds]);

  const neighbours = useMemo(() => {
    if (!focus || !data) return null;
    const ids = new Set([focus]);
    for (const e of data.edges) {
      if (e.from === focus) ids.add(e.to);
      if (e.to === focus) ids.add(e.from);
    }
    return ids;
  }, [focus, data]);

  if (error && !data) return <Failed error={error.includes("404") ? "This scan has no passive intelligence to graph." : error} onRetry={reload} />;
  if (!data) return <Skeleton className="mx-6 mb-6 h-[520px]" />;
  if (!data.nodes.length) return <Empty>Nothing to graph.</Empty>;

  const maxW = Math.max(1, ...data.nodes.map((v) => v.weight));
  // Layout units per screen pixel, so markers, links and labels keep their on-screen size at any zoom.
  // The drawing is fitted ("meet"), so the tighter of width and height sets the scale.
  const boxW = Math.max(320, svg.current?.clientWidth ?? 1080);
  const boxH = Math.max(200, svg.current?.clientHeight ?? 560);
  const u = 1 / Math.min(boxW / (bounds.w / view.s), boxH / (bounds.h / view.s));
  const radius = (v: GNode) => u * (v.kind === "domain" ? 9 : 4 + 5 * Math.sqrt(v.weight / maxW));
  const labelAll = data.nodes.length <= 40;
  const vb = `${bounds.minX + view.x} ${bounds.minY + view.y} ${bounds.w / view.s} ${bounds.h / view.s}`;
  const zoom = (f: number) => setView((v) => ({ ...v, s: Math.min(8, Math.max(0.4, v.s * f)) }));

  const onWheel = (e: WheelEvent) => {
    if (!e.ctrlKey && !e.metaKey) return; // plain scrolling scrolls the page
    e.preventDefault();
    zoom(e.deltaY < 0 ? 1.15 : 1 / 1.15);
  };
  const onDown = (e: PointerEvent) => {
    drag.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  };
  const onMove = (e: PointerEvent) => {
    if (!drag.current || !svg.current) return;
    const scale = bounds.w / view.s / svg.current.clientWidth;
    setView((v) => ({ ...v, x: drag.current!.vx - (e.clientX - drag.current!.x) * scale, y: drag.current!.vy - (e.clientY - drag.current!.y) * scale }));
  };

  const kinds = [...new Set(data.nodes.map((v) => v.kind))];
  return (
    <div className="px-5 pb-6 sm:px-6">
      <div className="mb-3 flex flex-wrap items-center gap-x-4 gap-y-2 text-[12.5px] text-ink-muted">
        {kinds.map((k) => (
          <span key={k} className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: token(KIND[k]?.color ?? "ink-muted") }} />
            {KIND[k]?.label ?? k}
          </span>
        ))}
        <span className="flex items-center gap-1.5">
          <span className="w-5 border-t border-dashed border-ink-faint" /> inferred
        </span>
        <label className="ml-auto flex items-center gap-2">
          <input type="checkbox" className="h-4 w-4 accent-[#1F6BFF]" checked={historical} onChange={(e) => setHistorical(e.target.checked)} /> Include hosts that no longer resolve
        </label>
      </div>
      <div className="relative overflow-hidden rounded-card border border-line bg-bg">
        <svg
          ref={svg}
          viewBox={vb}
          className={`block h-[560px] w-full touch-none select-none ${drag.current ? "cursor-grabbing" : "cursor-grab"} ${loading ? "opacity-60" : ""}`}
          onWheel={onWheel}
          onPointerDown={onDown}
          onPointerMove={onMove}
          onPointerUp={() => (drag.current = null)}
          onPointerLeave={() => (drag.current = null)}
          role="img"
          aria-label={`Infrastructure of ${data.target}: ${data.nodes.length} nodes`}
        >
          {data.edges.map((e, i) => {
            const a = pos.get(e.from);
            const b = pos.get(e.to);
            if (!a || !b) return null;
            const lit = !neighbours || (neighbours.has(e.from) && neighbours.has(e.to));
            return (
              <line
                key={i}
                x1={a.x}
                y1={a.y}
                x2={b.x}
                y2={b.y}
                stroke={token(lit && neighbours ? "accent-soft" : "accent-muted", neighbours ? (lit ? 0.9 : 0.12) : 0.38)}
                strokeWidth={u * (lit && neighbours ? 1.8 : 1.1)}
                strokeDasharray={e.evidence === "inferred" ? `${4 * u} ${4 * u}` : undefined}
              />
            );
          })}
          {data.nodes.map((v) => {
            const p = pos.get(v.id);
            if (!p) return null;
            const dim = neighbours && !neighbours.has(v.id);
            const r = radius(v);
            const flagged = v.flags?.some((f) => ["exposed", "kev", "dangling", "high-interest"].includes(f));
            const showLabel = labelAll || v.kind === "domain" || v.kind === "provider" || v.kind === "asn" || (neighbours?.has(v.id) ?? false) || hover?.id === v.id;
            return (
              <g
                key={v.id}
                opacity={dim ? 0.2 : 1}
                onPointerEnter={() => setHover(v)}
                onPointerLeave={() => setHover(undefined)}
                onClick={(e) => {
                  e.stopPropagation();
                  setFocus((f) => (f === v.id ? undefined : v.id));
                }}
                className="cursor-pointer"
              >
                {flagged && <circle cx={p.x} cy={p.y} r={r + 4 * u} fill="none" stroke={token("down", 0.8)} strokeWidth={1.5 * u} />}
                <circle cx={p.x} cy={p.y} r={r} fill={token(KIND[v.kind]?.color ?? "ink-muted")} stroke={token("bg")} strokeWidth={1.5 * u} />
                {showLabel && (
                  <text x={p.x + r + 4 * u} y={p.y + 4 * u} fontSize={11.5 * u} fill={token(v.kind === "domain" ? "ink" : "ink-muted", 0.95)} className="pointer-events-none">
                    {v.label.length > 34 ? `${v.label.slice(0, 32)}…` : v.label}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
        <div className="absolute right-3 top-3 flex flex-col gap-1">
          <button className="btn-ghost h-8 w-8 !px-0" onClick={() => zoom(1.25)} aria-label="Zoom in"><Plus className="h-4 w-4" /></button>
          <button className="btn-ghost h-8 w-8 !px-0" onClick={() => zoom(0.8)} aria-label="Zoom out"><Minus className="h-4 w-4" /></button>
          <button className="btn-ghost h-8 w-8 !px-0" onClick={() => { setView({ x: 0, y: 0, s: 1 }); setFocus(undefined); }} aria-label="Fit"><Maximize2 className="h-4 w-4" /></button>
        </div>
        {hover && (
          <div className="pointer-events-none absolute bottom-3 left-3 max-w-sm rounded-ctl border border-line bg-card-2/95 px-3 py-2 text-[12.5px] shadow-xl">
            <p className="font-mono text-[13px] text-ink">{hover.label}</p>
            <p className="text-ink-muted">
              {KIND[hover.kind]?.label ?? hover.kind}
              {hover.weight > 1 && ` · ${hover.weight} hosts`}
              {hover.detail && ` · ${hover.detail}`}
            </p>
            {hover.flags?.length ? <p className="text-down">{hover.flags.join(", ")}</p> : null}
          </div>
        )}
      </div>
      <p className="mt-2 text-[12.5px] text-ink-faint">
        {data.nodes.length} nodes · {data.edges.length} links · drag to pan, Ctrl+scroll or the buttons to zoom, click a node to highlight what it connects to
        {data.truncated && ` · ${data.omitted_hosts ?? 0} hosts left out to keep it readable`}
      </p>
    </div>
  );
}
