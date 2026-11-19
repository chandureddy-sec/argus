import {
  ChevronDown,
  Crosshair,
  Home,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Search,
  Settings,
  ShieldBan,
  ShieldCheck,
  X,
  type LucideIcon,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import type { Me } from "../lib/api";
import { Avatar, Logo, PRODUCT } from "./ui";

/** `to` is an Argus page; `href` anything else (an external page). */
interface Child {
  label: string;
  to?: string;
  href?: string;
  end?: boolean;
}

interface Item {
  label: string;
  icon: LucideIcon;
  href?: string;
  children?: Child[];
}

const NAV: Item[] = [
  {
    label: "Home",
    icon: Home,
    children: [
      { label: "Overview", to: "/", end: true },
      { label: "Threat landscape", to: "/landscape" },
      { label: "Assets", to: "/assets" },
    ],
  },
  {
    label: "Attack surface",
    icon: Radar,
    children: [
      { label: "New scan", to: "/scans/new" },
      { label: "Scans", to: "/scans", end: true },
      { label: "Compare", to: "/scans/compare" },
      { label: "Monitors", to: "/monitors" },
    ],
  },
  {
    label: "Threat intel",
    icon: Crosshair,
    children: [
      { label: "Verify", to: "/verify" },
      { label: "Bulk check", to: "/bulk" },
      { label: "Indicators", to: "/indicators" },
      { label: "Vulnerabilities", to: "/vulnerabilities" },
      { label: "ATT&CK", to: "/attack" },
      { label: "Detections", to: "/detections" },
      { label: "Lookalike domains", to: "/lookalikes" },
      { label: "Report assistant", to: "/assistant" },
      { label: "Products", to: "/products" },
    ],
  },
  {
    label: "Response",
    icon: ShieldBan,
    children: [
      { label: "Cases", to: "/cases" },
      { label: "Blocklist", to: "/blocklist" },
      { label: "Alerts", to: "/alerts" },
      { label: "Lab endpoints", to: "/endpoints" },
    ],
  },
  {
    label: "Platform",
    icon: Settings,
    children: [
      { label: "Feed catalog", to: "/feeds" },
      { label: "Integrations", to: "/integrations" },
      { label: "Settings", to: "/settings" },
      { label: "Audit log", to: "/audit" },
      { label: "Search", to: "/search" },
    ],
  },
];

function isActive(path: string, c: Child): boolean {
  if (!c.to) return false;
  return c.end ? path === c.to : path === c.to || path.startsWith(`${c.to}/`);
}

/** Groups that start expanded on a cold load: the two areas of the daily analyst
 * loop (PRODUCT.md). Response and Platform stay collapsed to keep the rail quiet;
 * any group with an active child also opens. Named instead of inlined so the
 * default is self-documenting rather than a magic condition. */
const DEFAULT_OPEN: ReadonlySet<string> = new Set(["Attack surface", "Threat intel"]);

/** True at the `lg` breakpoint (1024px) — the seam where the sidebar can become a
 * rail. Read synchronously on first render so the layout never flashes. */
function useIsDesktop(): boolean {
  const [isDesktop, setIsDesktop] = useState(() =>
    typeof window !== "undefined" ? window.matchMedia("(min-width: 1024px)").matches : true,
  );
  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const onChange = () => setIsDesktop(mq.matches);
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);
  return isDesktop;
}

/** Expanded group: a collapsible accordion with nested children. */
function Group({ item }: { item: Item }) {
  const path = useLocation().pathname;
  const hasActive = item.children?.some((c) => isActive(path, c)) ?? false;
  const [open, setOpen] = useState(hasActive || DEFAULT_OPEN.has(item.label));
  useEffect(() => {
    if (hasActive) setOpen(true);
  }, [hasActive]);
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
          {item.children.map((c) => {
            const active = isActive(path, c);
            const cls2 = `relative flex h-9 items-center justify-between rounded-ctl px-3 text-[13.5px] transition-colors ${
              active
                ? "bg-tint font-medium text-ink before:absolute before:-left-[13px] before:top-1/2 before:h-5 before:w-[2px] before:-translate-y-1/2 before:rounded-full before:bg-accent"
                : "text-ink-muted hover:bg-card-2 hover:text-ink"
            }`;
            return (
              <li key={c.label}>
                {c.to ? (
                  <Link to={c.to} aria-current={active ? "page" : undefined} className={cls2}>
                    {c.label}
                  </Link>
                ) : (
                  <a href={c.href} className={cls2}>
                    {c.label}
                  </a>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </li>
  );
}

/** Collapsed-rail group: an icon button that opens an accessible flyout menu of the
 * group's children. Works with mouse (hover + click), keyboard (Enter/Space/Arrow to
 * open, Arrow to move, Esc to close and return focus) and touch (tap = click). */
function RailGroup({ item }: { item: Item }) {
  const path = useLocation().pathname;
  const hasActive = item.children?.some((c) => isActive(path, c)) ?? false;
  const [open, setOpen] = useState(false);
  const btnRef = useRef<HTMLButtonElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const Icon = item.icon;

  // Close on an outside pointer or Escape; Escape returns focus to the trigger.
  useEffect(() => {
    if (!open) return;
    const onDown = (e: PointerEvent) => {
      const t = e.target as Node;
      if (!panelRef.current?.contains(t) && !btnRef.current?.contains(t)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        btnRef.current?.focus();
      }
    };
    document.addEventListener("pointerdown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const items = () => Array.from(panelRef.current?.querySelectorAll<HTMLElement>("[role='menuitem']") ?? []);
  const openAndFocus = (which: "first" | "last") => {
    setOpen(true);
    requestAnimationFrame(() => {
      const els = items();
      (which === "first" ? els[0] : els[els.length - 1])?.focus();
    });
  };
  const onTriggerKey = (e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown" || e.key === "ArrowRight") {
      e.preventDefault();
      openAndFocus("first");
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      openAndFocus("last");
    }
  };
  const onMenuKey = (e: React.KeyboardEvent) => {
    const els = items();
    const i = els.indexOf(document.activeElement as HTMLElement);
    if (e.key === "ArrowDown") {
      e.preventDefault();
      els[Math.min(i + 1, els.length - 1)]?.focus();
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      els[Math.max(i - 1, 0)]?.focus();
    } else if (e.key === "Home") {
      e.preventDefault();
      els[0]?.focus();
    } else if (e.key === "End") {
      e.preventDefault();
      els[els.length - 1]?.focus();
    } else if (e.key === "Tab") {
      setOpen(false); // Tab closes the menu and lets focus move on (W3C menu pattern)
    }
  };

  return (
    <li
      className="relative"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => {
        // Don't yank the menu away from a keyboard user whose focus is inside it.
        if (!panelRef.current?.contains(document.activeElement)) setOpen(false);
      }}
    >
      <button
        ref={btnRef}
        type="button"
        aria-haspopup="true"
        aria-expanded={open}
        aria-label={item.label}
        title={item.label}
        onClick={() => setOpen((o) => !o)}
        onKeyDown={onTriggerKey}
        className={`group flex h-10 w-10 items-center justify-center rounded-ctl transition-colors ${
          hasActive ? "bg-tint text-ink" : "text-ink-muted hover:bg-card-2 hover:text-ink"
        }`}
      >
        <Icon className={`h-[18px] w-[18px] ${hasActive ? "text-accent" : "text-ink-muted group-hover:text-ink"}`} />
      </button>
      {open && item.children && (
        <div
          ref={panelRef}
          role="menu"
          aria-label={item.label}
          onKeyDown={onMenuKey}
          className="absolute left-full top-0 z-50 min-w-[208px] rounded-card border border-line bg-card p-2 shadow-pop"
        >
          <p className="px-2 pb-1 pt-0.5 text-[11px] font-semibold uppercase tracking-wide text-ink-faint">{item.label}</p>
          <ul className="space-y-0.5">
            {item.children.map((c) => {
              const active = isActive(path, c);
              const cls = `flex h-9 items-center rounded-ctl px-3 text-[13.5px] transition-colors ${
                active ? "bg-tint font-medium text-ink" : "text-ink-muted hover:bg-card-2 hover:text-ink"
              }`;
              return (
                <li key={c.label}>
                  {c.to ? (
                    <Link role="menuitem" tabIndex={-1} to={c.to} aria-current={active ? "page" : undefined} className={cls} onClick={() => setOpen(false)}>
                      {c.label}
                    </Link>
                  ) : (
                    <a role="menuitem" tabIndex={-1} href={c.href} className={cls} onClick={() => setOpen(false)}>
                      {c.label}
                    </a>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </li>
  );
}

export default function Sidebar({
  open,
  onClose,
  me,
  collapsed = false,
  onToggle,
}: {
  open: boolean;
  onClose: () => void;
  me?: Me;
  collapsed?: boolean;
  onToggle?: () => void;
}) {
  const navigate = useNavigate();
  const isDesktop = useIsDesktop();
  // The rail is a desktop-only state; the mobile drawer is always the full sidebar.
  const rail = isDesktop && collapsed;

  return (
    <>
      {/* mobile backdrop */}
      <div
        onClick={onClose}
        className={`fixed inset-0 z-30 bg-bg/70 backdrop-blur-sm transition-opacity lg:hidden ${open ? "opacity-100" : "pointer-events-none opacity-0"}`}
        aria-hidden="true"
      />
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex flex-col border-r border-line bg-card transition-[transform,width] duration-200 lg:translate-x-0 ${
          rail ? "w-[64px]" : "w-[260px] lg:w-[240px]"
        } ${open ? "translate-x-0" : "-translate-x-full"}`}
        aria-label="Main navigation"
      >
        {rail ? (
          <>
            <div className="flex items-center justify-center pb-4 pt-5">
              <Link to="/" title={PRODUCT.name} aria-label={PRODUCT.name}>
                <Logo size={30} />
              </Link>
            </div>
            <div className="flex justify-center pb-3">
              <Link
                to="/search"
                title="Search"
                aria-label="Search"
                className="flex h-10 w-10 items-center justify-center rounded-ctl text-ink-muted transition-colors hover:bg-card-2 hover:text-ink"
              >
                <Search className="h-[18px] w-[18px]" />
              </Link>
            </div>
            <nav className="flex-1 overflow-visible px-3 pb-4" aria-label="Sections">
              <ul className="flex flex-col items-center gap-1">
                {NAV.map((item) => (
                  <RailGroup key={item.label} item={item} />
                ))}
              </ul>
            </nav>
            <div className="flex flex-col items-center gap-3 border-t border-line py-4">
              <Link to="/verify" title="Verify an indicator" aria-label="Verify an indicator" className="btn-primary h-10 w-10 !px-0">
                <Crosshair className="h-4 w-4" />
              </Link>
              <Avatar initials={me?.initials ?? "…"} />
              <button
                type="button"
                onClick={onToggle}
                aria-pressed={true}
                aria-label="Expand sidebar"
                title="Expand sidebar"
                className="flex h-9 w-9 items-center justify-center rounded-ctl text-ink-muted transition-colors hover:bg-card-2 hover:text-ink"
              >
                <PanelLeftOpen className="h-[18px] w-[18px]" />
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-3 px-5 pb-4 pt-5">
              <Link to="/" className="flex min-w-0 flex-1 items-center gap-3">
                <Logo size={34} />
                <span className="min-w-0">
                  <span className="block text-[17px] font-bold tracking-tight">{PRODUCT.name}</span>
                  <span className="block truncate text-[11px] text-ink-faint">{PRODUCT.tagline}</span>
                </span>
              </Link>
              {onToggle && (
                <button
                  type="button"
                  onClick={onToggle}
                  aria-pressed={false}
                  aria-label="Collapse sidebar"
                  title="Collapse sidebar"
                  className="hidden rounded-ctl p-1.5 text-ink-muted transition-colors hover:bg-card-2 hover:text-ink lg:inline-flex"
                >
                  <PanelLeftClose className="h-[18px] w-[18px]" />
                </button>
              )}
              <button onClick={onClose} className="rounded-ctl p-1.5 text-ink-muted hover:text-ink lg:hidden" aria-label="Close menu">
                <X className="h-5 w-5" />
              </button>
            </div>

            <form
              className="px-4 pb-3"
              role="search"
              onSubmit={(e) => {
                e.preventDefault();
                const q = new FormData(e.currentTarget).get("q");
                if (typeof q === "string" && q.trim()) navigate(`/search?q=${encodeURIComponent(q.trim())}`);
              }}
            >
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
                    <Link to="/settings" className="hover:text-accent-soft">
                      Settings
                    </Link>
                  </p>
                </div>
              </div>
              <Link className="btn-primary h-10 w-full" to="/verify">
                <Crosshair className="h-4 w-4" />
                Verify an indicator
              </Link>
            </div>
          </>
        )}
      </aside>
    </>
  );
}
