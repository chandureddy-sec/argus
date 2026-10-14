import {
  Activity,
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
  Users,
  X,
  type LucideIcon,
} from "lucide-react";
import { useState } from "react";
import { Avatar, Logo, PRODUCT } from "./ui";

interface Item {
  label: string;
  icon: LucideIcon;
  children?: { label: string; active?: boolean; badge?: string }[];
  badge?: string;
}

const NAV: Item[] = [
  {
    label: "Home",
    icon: Home,
    children: [{ label: "Overview" }, { label: "Reports", active: true }, { label: "Assets" }, { label: "Cases", badge: "3" }],
  },
  { label: "Attack surface", icon: Radar, children: [{ label: "New scan" }, { label: "Scans" }, { label: "Compare" }, { label: "Monitors" }] },
  { label: "Threat intel", icon: Crosshair, children: [{ label: "Verify" }, { label: "Bulk check" }, { label: "Indicators" }, { label: "ATT&CK" }] },
  { label: "Vulnerabilities", icon: Gauge },
  { label: "Blocklist", icon: ShieldBan, badge: "12" },
  { label: "Feed catalog", icon: Database },
  { label: "Activity log", icon: Activity },
  { label: "Users", icon: Users },
  { label: "Settings", icon: Settings },
  { label: "Documentation", icon: BookOpen },
];

function Group({ item }: { item: Item }) {
  const hasActive = item.children?.some((c) => c.active) ?? false;
  const [open, setOpen] = useState(hasActive);
  const Icon = item.icon;
  return (
    <li>
      <button
        onClick={() => item.children && setOpen(!open)}
        aria-expanded={item.children ? open : undefined}
        className={`group flex h-10 w-full items-center gap-3 rounded-ctl px-3 text-[14px] font-medium transition-colors ${
          hasActive ? "text-ink" : "text-ink-muted hover:bg-card-2 hover:text-ink"
        }`}
      >
        <Icon className={`h-[18px] w-[18px] ${hasActive ? "text-accent" : "text-ink-muted group-hover:text-ink"}`} />
        <span className="flex-1 text-left">{item.label}</span>
        {item.badge && <span className="rounded-full bg-accent/15 px-2 text-[11px] font-semibold text-accent-soft">{item.badge}</span>}
        {item.children && <ChevronDown className={`h-4 w-4 transition-transform ${open ? "rotate-180" : ""}`} />}
      </button>
      {item.children && open && (
        <ul className="relative mb-1 ml-[21px] mt-0.5 space-y-0.5 border-l border-line pl-3">
          {item.children.map((c) => (
            <li key={c.label}>
              <a
                href="#"
                aria-current={c.active ? "page" : undefined}
                className={`relative flex h-9 items-center justify-between rounded-ctl px-3 text-[13.5px] transition-colors ${
                  c.active
                    ? "bg-accent/10 font-medium text-ink before:absolute before:-left-[13px] before:top-1/2 before:h-5 before:w-[2px] before:-translate-y-1/2 before:rounded-full before:bg-accent"
                    : "text-ink-muted hover:bg-card-2 hover:text-ink"
                }`}
              >
                {c.label}
                {c.badge && <span className="rounded-full bg-down/15 px-1.5 text-[11px] font-semibold text-down">{c.badge}</span>}
              </a>
            </li>
          ))}
        </ul>
      )}
    </li>
  );
}

export default function Sidebar({ open, onClose }: { open: boolean; onClose: () => void }) {
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

        <div className="px-4 pb-3">
          <label className="relative block">
            <span className="sr-only">Search</span>
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-faint" />
            <input className="ctl w-full pl-9" placeholder="Search IOC, asset, scan…" />
            <kbd className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-line px-1.5 text-[10px] text-ink-faint">
              /
            </kbd>
          </label>
        </div>

        <nav className="flex-1 overflow-y-auto px-3 pb-4">
          <ul className="space-y-0.5">
            {NAV.map((item) => (
              <Group key={item.label} item={item} />
            ))}
          </ul>
        </nav>

        <div className="border-t border-line p-4">
          <div className="mb-3 flex items-center gap-3">
            <Avatar initials="CR" />
            <div className="min-w-0">
              <p className="truncate text-[14px] font-semibold">Chandu Reddy</p>
              <a href="#" className="text-[12px] text-ink-muted hover:text-accent-soft">
                Account settings
              </a>
            </div>
            <ShieldCheck className="ml-auto h-4 w-4 text-up" aria-label="Admin" />
          </div>
          <button className="btn-primary h-10 w-full">
            <Radar className="h-4 w-4" />
            New scan
          </button>
        </div>
      </aside>
    </>
  );
}
