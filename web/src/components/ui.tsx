import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";
import { createPortal } from "react-dom";
import { useTheme } from "../lib/theme";

/** Working product name: one constant, so the final name is a one-line change. */
export const PRODUCT = { name: "Argus", tagline: "Recon + threat intel" };

/** A colour token as a concrete CSS colour. SVG presentation attributes (chart
 * fills, gradient stops) don't reliably resolve var(), so tokens are read from
 * :root once per theme; the CSS variables in index.css stay the single source. */
const cache = new Map<string, string>();
export function token(name: string, alpha = 1): string {
  const key = `${document.documentElement.dataset.theme ?? ""}:${name}`;
  let rgb = cache.get(key);
  if (rgb === undefined) {
    rgb = getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim() || "128 128 128";
    cache.set(key, rgb);
  }
  return `rgb(${rgb} / ${alpha})`;
}

/** token() for components: re-renders them when the theme changes. */
export function useToken(): (name: string, alpha?: number) => string {
  useTheme();
  return token;
}

export function Logo({ size = 32 }: { size?: number }) {
  const token = useToken();
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true">
      <defs>
        <linearGradient id="lg-mark" x1="8" y1="56" x2="56" y2="8" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor={token("accent")} />
          <stop offset="1" stopColor={token("olive-gold")} />
        </linearGradient>
      </defs>
      <rect x="3" y="3" width="58" height="58" rx="17" fill={token("card-2")} />
      <rect x="3" y="3" width="58" height="58" rx="17" fill="none" stroke="url(#lg-mark)" strokeWidth="2.5" />
      {/* a lens over a radar sweep: recon + threat intel */}
      <circle cx="29" cy="33" r="13" fill="none" stroke="url(#lg-mark)" strokeWidth="4.5" />
      <path d="M29 33 L38.5 23.5" stroke="url(#lg-mark)" strokeWidth="4.5" strokeLinecap="round" />
      <path d="M38.5 42.5 L46 50" stroke="url(#lg-mark)" strokeWidth="5" strokeLinecap="round" />
      <circle cx="48" cy="16" r="4" fill={token("terracotta")} />
    </svg>
  );
}

export function Change({ value, invert = false }: { value: number; invert?: boolean }) {
  // invert: for metrics where going down is good (time to verify, exposures)
  const good = invert ? value < 0 : value >= 0;
  return (
    <span
      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-semibold tabular-nums ${
        good ? "bg-up/10 text-up ring-1 ring-up/20" : "bg-down/10 text-down ring-1 ring-down/20"
      }`}
    >
      {value >= 0 ? "+" : ""}
      {value.toFixed(1)}%
    </span>
  );
}

export function Card({ children, className = "", delay = 0 }: { children: ReactNode; className?: string; delay?: number }) {
  return (
    <section className={`card animate-rise p-5 sm:p-6 ${className}`} style={{ animationDelay: `${delay}ms` }}>
      {children}
    </section>
  );
}

export function CardHead({ title, sub, children }: { title: string; sub?: string; children?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-[15px] font-semibold text-ink">{title}</h2>
        {sub && <p className="mt-1 label">{sub}</p>}
      </div>
      {children && <div className="flex flex-wrap items-center gap-2">{children}</div>}
    </header>
  );
}

export function Select({
  value,
  options,
  onChange,
  label,
}: {
  value: string;
  options: string[];
  onChange: (v: string) => void;
  label: string;
}) {
  return (
    <label className="relative inline-flex">
      <span className="sr-only">{label}</span>
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        className="ctl h-8 max-w-[220px] cursor-pointer appearance-none truncate pr-8 text-[13px] text-ink-muted hover:text-ink"
      >
        {options.map((o) => (
          <option key={o} value={o} className="bg-card text-ink">
            {o}
          </option>
        ))}
      </select>
      <ChevronDown className="pointer-events-none absolute right-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
    </label>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
}: {
  value: T;
  options: readonly T[];
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="tablist" aria-label={label} className="inline-flex rounded-ctl border border-ctl-line bg-card-2/60 p-0.5">
      {options.map((o) => (
        <button
          key={o}
          role="tab"
          aria-selected={o === value}
          onClick={() => onChange(o)}
          className={`h-7 rounded-[8px] px-3 text-[12.5px] font-medium transition-colors ${
            o === value ? "bg-accent text-on-accent shadow-glow" : "text-ink-muted hover:text-ink"
          }`}
        >
          {o}
        </button>
      ))}
    </div>
  );
}

export function Avatar({ initials, className = "" }: { initials: string; className?: string }) {
  return (
    <span
      className={`inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-accent text-[12px] font-semibold text-on-accent ring-2 ring-card ${className}`}
    >
      {initials}
    </span>
  );
}

export function Legend({ items }: { items: { name: string; color: string }[] }) {
  return (
    <ul className="flex flex-wrap items-center gap-4">
      {items.map((i) => (
        <li key={i.name} className="flex items-center gap-2 text-[13px] text-ink-muted">
          <span className="h-2.5 w-2.5 rounded-full" style={{ background: `rgb(var(--${i.color}))` }} />
          {i.name}
        </li>
      ))}
    </ul>
  );
}

/** "48.8K" style numbers for axes and tooltips. */
export function compact(n: number): string {
  return Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(n);
}

/** True when the user asked the OS for less motion; charts then draw without animating. */
export const reducedMotion =
  typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** A modal dialog's backdrop, rendered at the end of <body> so no card (an
 * animated or transformed ancestor would trap position:fixed) can clip it or
 * paint over it. Tall dialogs scroll. */
export function Overlay({ children, label }: { children: ReactNode; label?: string }) {
  return createPortal(
    <div role="dialog" aria-modal="true" aria-label={label} className="fixed inset-0 z-50 overflow-y-auto bg-scrim backdrop-blur-sm">
      <div className="flex min-h-full items-center justify-center p-4">{children}</div>
    </div>,
    document.body,
  );
}
