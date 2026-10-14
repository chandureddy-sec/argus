import { RotateCw } from "lucide-react";

/** Placeholder blocks while the first answer loads. */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`animate-pulse rounded-ctl bg-card-2 ${className}`} />;
}

export function Failed({ error, onRetry }: { error: string; onRetry: () => void }) {
  return (
    <div role="alert" className="flex flex-col items-center justify-center gap-3 py-10 text-center">
      <p className="text-[13.5px] text-ink-muted">
        Couldn't load this: <span className="text-down">{error}</span>
      </p>
      <button className="btn-ghost h-8 text-[13px]" onClick={onRetry}>
        <RotateCw className="h-3.5 w-3.5" /> Try again
      </button>
    </div>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return <p className="py-10 text-center text-[13.5px] text-ink-muted">{children}</p>;
}
