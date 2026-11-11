import { AlertTriangle, Inbox, RotateCw, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

/** Placeholder blocks while the first answer loads. `animate-pulse` is an
 * animation, so the global reduced-motion rule (which only quiets transitions
 * and `.animate-rise`) doesn't reach it — stop it here for people who ask for
 * less motion. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-ctl bg-card-2 motion-reduce:animate-none ${className}`} />;
}

/** A failed load: a quiet alert with a retry. `role="alert"` so assistive tech
 * announces it (error must not be colour-only). */
export function Failed({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <span className="inline-flex h-11 w-11 items-center justify-center rounded-full bg-down/10 text-down ring-1 ring-down/20">
        <AlertTriangle className="h-[22px] w-[22px]" />
      </span>
      <div className="space-y-1">
        <p className="text-[14px] font-medium text-ink">Couldn't load this</p>
        <p className="mx-auto max-w-sm text-[13px] text-ink-muted">{error}</p>
      </div>
      <button className="btn-ghost h-8 text-[13px]" onClick={onRetry}>
        <RotateCw className="h-3.5 w-3.5" /> Try again
      </button>
    </div>
  );
}

/** Nothing to show (yet). The message says what's missing; the optional `title`
 * and `action` let a caller add a heading and a next step, so an empty screen
 * still guides the analyst instead of going blank (ux guideline: never a bare
 * empty screen). Passing only children keeps the old one-line usage working. */
export function Empty({
  children,
  icon: Icon = Inbox,
  title,
  action,
}: {
  children: ReactNode;
  icon?: LucideIcon;
  title?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center gap-3 px-6 py-12 text-center">
      <span className="inline-flex h-11 w-11 items-center justify-center rounded-full bg-chip text-ink-faint ring-1 ring-line">
        <Icon className="h-[22px] w-[22px]" />
      </span>
      <div className="space-y-1">
        {title && <p className="text-[14px] font-medium text-ink">{title}</p>}
        <p className="mx-auto max-w-sm text-[13.5px] text-ink-muted">{children}</p>
      </div>
      {action && <div className="mt-1">{action}</div>}
    </div>
  );
}
