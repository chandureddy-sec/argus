import { Bell, ChevronRight, LogOut, Menu, Plus } from "lucide-react";
import type { Me } from "../lib/api";
import { Avatar } from "./ui";

export default function Topbar({ onMenu, me }: { onMenu: () => void; me?: Me }) {
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-line bg-bg/80 px-4 backdrop-blur-md sm:px-6 lg:px-8">
      <button onClick={onMenu} className="rounded-ctl p-2 text-ink-muted hover:bg-card hover:text-ink lg:hidden" aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </button>
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-[14px]">
        <a href="/app/" className="hidden text-ink-muted hover:text-ink sm:inline">
          Dashboard
        </a>
        <ChevronRight className="hidden h-4 w-4 shrink-0 text-ink-faint sm:block" />
        <span className="truncate font-medium text-ink" aria-current="page">
          Reports
        </span>
      </nav>
      <div className="ml-auto flex items-center gap-2 sm:gap-3">
        <a className="btn-primary" href="/ui/cases">
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">New case</span>
        </a>
        <a href="/ui/flagged" className="rounded-ctl border border-line bg-card p-2 text-ink-muted hover:text-ink" aria-label="Flagged by analysts" title="Flagged by analysts">
          <Bell className="h-[18px] w-[18px]" />
        </a>
        <Avatar initials={me?.initials ?? "…"} />
        {/* A real form POST: sign-out works the same with or without the app's script. */}
        <form method="post" action="/ui/logout" className="flex">
          <button type="submit" className="rounded-ctl p-2 text-ink-muted hover:bg-card hover:text-ink" title="Sign out" aria-label="Sign out">
            <LogOut className="h-[18px] w-[18px]" />
          </button>
        </form>
      </div>
    </header>
  );
}
