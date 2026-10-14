import {
  BookOpen,
  ChevronDown,
  Crosshair,
  Database,
  Gauge,
  Home,
  Radar,
  Search,
  Settings,
  ShieldBan,
  ShieldCheck,
  X,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import type { Me } from "../lib/api";
import { Avatar, Logo, PRODUCT } from "./ui";

interface Item {
  label: string;
  icon: LucideIcon;
  href?: string;
  children?: { label: string; href: string; active?: boolean; soon?: boolean }[];
}

// Pages not yet rebuilt in Argus open the classic ThreatLens screens (/ui) until they are;
// "soon" marks the ReconX pages that arrive with the engine (step 2).
const NAV: Item[] = [
  {
    label: "Home",
    icon: Home,
    children: [
      { label: "Overview", href: "/ui" },
      { label: "Reports", href: "/app/", active: true },
      { label: "Assets", href: "/ui/assets" },
      { label: "Cases", href: "/ui/cases" },
    ],
  },
  {
    label: "Attack surface",
    icon: Radar,
    children: [
      { label: "New scan", href: "#", soon: true },
      { label: "Scans", href: "#", soon: true },
      { label: "Compare", href: "#", soon: true },
      { label: "Monitors", href: "#", soon: true },
    ],
  },
  {
    label: "Threat intel",
    icon: Crosshair,
    children: [
      { label: "Verify", href: "/ui/verify" },
      { label: "Bulk check", href: "/ui/lookup" },
      { label: "Indicators", href: "/ui/indicators" },
      { label: "ATT&CK", href: "/ui/attack" },
    ],
  },
  { label: "Vulnerabilities", icon: Gauge, href: "/ui/vulnerabilities" },
  { label: "Blocklist", icon: ShieldBan, href: "/ui/blocklist" },
  { label: "Feed catalog", icon: Database, href: "/ui/sources" },
  { label: "Search", icon: Search, href: "/ui/search" },
  { label: "Settings", icon: Settings, href: "/ui/settings" },
  { label: "Sources & licences", icon: BookOpen, href: "/ui/sources#feeds" },
];

function Group({ item }: { item: Item }) {
  const hasActive = item.children?.some((c) => c.active) ?? false;
  const [open, setOpen] = useState(hasActive);
  const Icon = item.icon;
  const cls = `group flex h-10 w-full items-center gap-3 rounded-ctl px-3 text-[14px] font-medium transition-colors ${
    hasActive ? "text-ink" : "text-ink-muted hover:bg-card-2 hover:text-ink"
  }`;
  const inner = (
    <>
      <Icon className={`h-[18px] w-[18px] ${hasActive ? "text-accent" : "text-ink-muted group-hover:text-ink"}`} />
      <span className="flex-1 text-left">{item.label}</span>
      {item.children && <ChevronDown className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />}
    </>
  );
  return (
    <li>
      {item.children ? (
        <button onClick={() => setOpen(!open)} aria-expanded={open} className={cls}>
          {inner}
        </button>
      ) : (
        <a href={item.href} className={cls}>
          {inner}
        </a>
      )}
      {item.children && open && (
        <ul className="relative mb-1 ml-[21px] mt-0.5 space-y-0.5 border-l border-line pl-3">
          {item.children.map((c) => (
            <li key={c.label}>
              <a
                href={c.href}
                aria-current={c.active ? "page" : undefined}
                aria-disabled={c.soon || undefined}
                onClick={(e) => c.soon && e.preventDefault()}
                className={`relative flex h-9 items-center justify-between rounded-ctl px-3 text-[13.5px] transition-colors ${
                  c.active
                    ? "bg-accent/10 font-medium text-ink before:absolute before:-left-[13px] before:top-1/2 before:h-5 before:w-[2px] before:-translate-y-1/2 before:rounded-full before:bg-accent"
                    : c.soon
                      ? "cursor-default text-ink-faint"
                      : "text-ink-muted hover:bg-card-2 hover:text-ink"
                }`}
              >
                {c.label}
                {c.soon && <span className="rounded-full border border-line px-1.5 text-[10.5px] text-ink-faint">soon</span>}
              </a>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export default function Sidebar({ open, onClose, me }: { open: boolean; onClose: () => void; me?: Me }) {
  return (
    <>
      {/* mobile backdrop */}
      <div
        onClick={onClose}
        className={`fixed inset-0 z-30 bg-bg/70 backdrop-blur-sm transition-opacity lg:hidden ${open ? "opacity-100" : "pointer-events-none opacity-0"}`}
        aria-hidden="true"
      />
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-[260px] flex-col border-r border-line bg-card transition-transform duration-300 lg:w-[240px] lg:translate-x-0 ${
          open ? "translate-x-0" : "-translate-x-full"
        }`}
        aria-label="Main navigation"
      >
        <div className="flex items-center gap-3 px-5 pb-4 pt-5">
          <Logo size={34} />
          <div className="min-w-0 flex-1">
            <p className="text-[17px] font-bold tracking-tight">{PRODUCT.name}</p>
            <p className="truncate text-[11px] text-ink-faint">{PRODUCT.tagline}</p>
          </div>
          <button onClick={onClose} className="rounded-ctl p-1.5 text-ink-muted hover:text-ink lg:hidden" aria-label="Close menu">
            <X className="h-5 w-5" />
          </button>
        </div>

        <form className="px-4 pb-3" method="get" action="/ui/search" role="search">
          <label className="relative block">
            <span className="sr-only">Search</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input name="q" className="ctl w-full pl-9" placeholder="Search IOC, CVE, malware…" maxLength={200} />
          </label>
        </form>

        <nav className="flex-1 overflow-y-auto px-3 pb-4">
          <ul className="space-y-0.5">
            {NAV.map((item) => (
              <Group key={item.label} item={item} />
            ))}
          </ul>
        </nav>

        <div className="border-t border-line p-4">
          <div className="mb-3 flex items-center gap-3">
            <Avatar initials={me?.initials ?? "…"} />
            <div className="min-w-0 flex-1">
              <p className="truncate text-[14px] font-semibold" title={me?.name}>
                {me?.name ?? "Signed in"}
              </p>
              <p className="flex items-center gap-1 truncate text-[12px] text-ink-muted" title={me ? `Reads up to ${me.clearance}` : undefined}>
                {me && <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-up" />}
                <span className="capitalize">{me?.role ?? ""}</span>
                <span className="text-ink-faint">·</span>
                <a href="/ui/settings" className="hover:text-accent-soft">
                  Account
                </a>
              </p>
            </div>
          </div>
          <a className="btn-primary h-10 w-full" href="/ui/verify">
            <Crosshair className="h-4 w-4" />
            Verify an indicator
          </a>
        </div>
      </aside>
    </>
  );
}
