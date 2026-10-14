import { Bell, ChevronRight, LogOut, Menu, Plus } from "lucide-react";
import { Link } from "react-router-dom";
import { signOut, type Me } from "../lib/api";
import { Avatar } from "./ui";

export default function Topbar({ onMenu, me, crumbs }: { onMenu: () => void; me?: Me; crumbs: string[] }) {
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-line bg-bg/80 px-4 backdrop-blur-md sm:px-6 lg:px-8">
      <button onClick={onMenu} className="rounded-ctl p-2 text-ink-muted hover:bg-card hover:text-ink lg:hidden" aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </button>
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-[14px]">
        <Link to="/" className="hidden text-ink-muted hover:text-ink sm:inline">
          Dashboard
        </Link>
        {crumbs.map((c, i) => {
          const last = i === crumbs.length - 1;
          return (
            <span key={`${i}-${c}`} className={`min-w-0 items-center gap-1.5 ${last ? "flex" : "hidden sm:flex"}`}>
              <ChevronRight className="hidden h-4 w-4 shrink-0 text-ink-faint sm:block" />
              <span className={`truncate ${last ? "font-medium text-ink" : "text-ink-muted"}`} aria-current={last ? "page" : undefined}>
                {c}
              </span>
            </span>
          );
        })}
      </nav>
      <div className="ml-auto flex items-center gap-2 sm:gap-3">
        <Link className="btn-primary" to="/scans/new">
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New scan</span>
        </Link>
        <Link to="/landscape#activity" className="rounded-ctl border border-line bg-card p-2 text-ink-muted hover:text-ink" aria-label="This week's activity" title="This week's activity">
          <Bell className="h-[18px] w-[18px]" />
        </Link>
        <Avatar initials={me?.initials ?? "…"} />
        <button onClick={signOut} className="rounded-ctl p-2 text-ink-muted hover:bg-card hover:text-ink" title="Sign out" aria-label="Sign out">
          <LogOut className="h-[18px] w-[18px]" />
        </button>
      </div>
    </header>
  );
}
