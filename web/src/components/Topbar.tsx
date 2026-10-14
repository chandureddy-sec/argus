import { Bell, ChevronRight, Menu, Plus } from "lucide-react";
import { Avatar } from "./ui";

export default function Topbar({ onMenu }: { onMenu: () => void }) {
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-line bg-bg/80 px-4 backdrop-blur-md sm:px-6 lg:px-8">
      <button onClick={onMenu} className="rounded-ctl p-2 text-ink-muted hover:bg-card hover:text-ink lg:hidden" aria-label="Open menu">
        <Menu className="h-5 w-5" />
      </button>
      <nav aria-label="Breadcrumb" className="flex min-w-0 items-center gap-1.5 text-[14px]">
        <a href="#" className="text-ink-muted hover:text-ink">
          Dashboard
        </a>
        <ChevronRight className="h-4 w-4 shrink-0 text-ink-faint" />
        <span className="truncate font-medium text-ink" aria-current="page">
          Reports
        </span>
      </nav>
      <div className="ml-auto flex items-center gap-2 sm:gap-3">
        <button className="btn-primary">
          <Plus className="h-4 w-4" />
          <span className="hidden sm:inline">Create report</span>
        </button>
        <button className="relative rounded-ctl border border-line bg-card p-2 text-ink-muted hover:text-ink" aria-label="Notifications, 4 new">
          <Bell className="h-[18px] w-[18px]" />
          <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-accent ring-2 ring-card" />
        </button>
        <Avatar initials="CR" />
      </div>
    </header>
  );
}
