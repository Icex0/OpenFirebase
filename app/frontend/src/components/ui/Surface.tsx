import type { HTMLAttributes } from "react";
import { cn } from "@/lib/cn";

/** Container with hairline border — used in place of heavy card/shadow look. */
export function Surface({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...rest}
      className={cn("rounded-lg border border-ink-700/80 bg-ink-900/40", className)}
    />
  );
}

export function SurfaceHeader({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      {...rest}
      className={cn(
        "flex items-center justify-between gap-4 border-b border-ink-700/60 px-4 py-3",
        className,
      )}
    />
  );
}

export function SurfaceBody({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div {...rest} className={cn("p-4", className)} />;
}
