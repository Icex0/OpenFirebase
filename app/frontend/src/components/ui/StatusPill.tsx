import { cn } from "@/lib/cn";
import type { ScanStatus } from "@/lib/types";

const STYLES: Record<ScanStatus, string> = {
  queued: "text-ink-300 before:bg-ink-400",
  running: "text-accent before:bg-accent before:animate-pulse",
  done: "text-emerald-300 before:bg-emerald-400",
  failed: "text-severity-public before:bg-severity-public",
  cancelled: "text-ink-400 before:bg-ink-500",
};

const LABELS: Record<ScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  done: "Complete",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function StatusPill({ status }: { status: ScanStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider",
        "before:h-1.5 before:w-1.5 before:rounded-full",
        STYLES[status],
      )}
    >
      {LABELS[status]}
    </span>
  );
}
