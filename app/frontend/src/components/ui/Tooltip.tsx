import * as RTooltip from "@radix-ui/react-tooltip";

import { cn } from "@/lib/cn";

export const TooltipProvider = RTooltip.Provider;

interface TooltipProps {
  content: React.ReactNode;
  children: React.ReactNode;
  side?: "top" | "right" | "bottom" | "left";
  align?: "start" | "center" | "end";
  delayDuration?: number;
  className?: string;
}

export function Tooltip({
  content,
  children,
  side = "top",
  align = "start",
  delayDuration = 150,
  className,
}: TooltipProps) {
  return (
    <RTooltip.Root delayDuration={delayDuration}>
      <RTooltip.Trigger asChild>{children}</RTooltip.Trigger>
      <RTooltip.Portal>
        <RTooltip.Content
          side={side}
          align={align}
          sideOffset={6}
          collisionPadding={12}
          className={cn(
            "z-50 max-w-sm overflow-hidden rounded-md border border-ink-700/80 bg-ink-900/95 px-3 py-2 text-[12px] text-ink-100 shadow-xl shadow-black/40 backdrop-blur-sm",
            "data-[state=delayed-open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=delayed-open]:fade-in-0 data-[state=delayed-open]:zoom-in-95 data-[state=closed]:zoom-out-95",
            className,
          )}
        >
          {content}
          <RTooltip.Arrow className="fill-ink-700/80" width={10} height={5} />
        </RTooltip.Content>
      </RTooltip.Portal>
    </RTooltip.Root>
  );
}
