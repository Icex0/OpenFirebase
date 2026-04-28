import { cn } from "@/lib/cn";
import type { ScanStage } from "@/lib/types";

const STEPS: { key: Exclude<ScanStage, "failed">; label: string }[] = [
  { key: "queued", label: "Queued" },
  { key: "extracting", label: "Extracting" },
  { key: "extracted", label: "Extracted" },
  { key: "scanning", label: "Scanning" },
  { key: "done", label: "Done" },
];

export function StageTimeline({ stage }: { stage: ScanStage }) {
  const failed = stage === "failed";
  const activeIdx = failed
    ? -1
    : STEPS.findIndex((s) => s.key === stage);

  return (
    <ol className="flex flex-wrap items-center gap-0">
      {STEPS.map((step, i) => {
        const done = !failed && i < activeIdx;
        const active = !failed && i === activeIdx;
        return (
          <li key={step.key} className="flex items-center">
            <div className="flex items-center gap-2">
              <span
                className={cn(
                  "h-2 w-2 rounded-full",
                  done && "bg-accent",
                  active && "bg-accent animate-pulse",
                  !done && !active && "bg-ink-700",
                )}
              />
              <span
                className={cn(
                  "font-mono text-[11px] uppercase tracking-wider",
                  active && "text-ink-100",
                  done && "text-ink-300",
                  !done && !active && "text-ink-500",
                )}
              >
                {step.label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <span
                className={cn(
                  "mx-3 h-px w-6 sm:w-10",
                  done ? "bg-accent/60" : "bg-ink-700",
                )}
              />
            )}
          </li>
        );
      })}
      {failed && (
        <li className="ml-3 flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-severity-public" />
          <span className="font-mono text-[11px] uppercase tracking-wider text-severity-public">
            Failed
          </span>
        </li>
      )}
    </ol>
  );
}
