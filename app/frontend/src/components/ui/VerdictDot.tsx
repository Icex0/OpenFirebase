import { cn } from "@/lib/cn";
import type { Verdict } from "@/lib/types";
import { VERDICT_DOT, VERDICT_LABEL } from "@/lib/verdict";

interface Props {
  verdict: Verdict;
  subdued?: boolean;
}

export function VerdictDot({ verdict, subdued }: Props) {
  return (
    <span className="inline-flex items-center gap-2">
      <span
        className={cn(
          "h-2 w-2 rounded-full ring-1 ring-inset ring-black/30",
          VERDICT_DOT[verdict],
        )}
        aria-hidden
      />
      <span
        className={cn(
          "text-xs font-medium",
          subdued ? "text-ink-300" : "text-ink-100",
        )}
      >
        {VERDICT_LABEL[verdict]}
      </span>
    </span>
  );
}
