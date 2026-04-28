import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

type Variant = "primary" | "ghost" | "danger";
type Size = "sm" | "md";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  leading?: ReactNode;
}

const VARIANTS: Record<Variant, string> = {
  primary:
    "bg-accent text-ink-950 hover:bg-accent-hover disabled:bg-ink-700 disabled:text-ink-400",
  ghost:
    "bg-transparent text-ink-200 hover:bg-ink-800 border border-ink-700 hover:border-ink-600",
  danger:
    "bg-transparent text-severity-public border border-severity-public/40 hover:bg-severity-public/10",
};

const SIZES: Record<Size, string> = {
  sm: "h-7 px-2.5 text-xs",
  md: "h-9 px-3.5 text-sm",
};

export function Button({
  variant = "primary",
  size = "md",
  leading,
  className,
  children,
  ...rest
}: Props) {
  return (
    <button
      {...rest}
      className={cn(
        "inline-flex items-center gap-2 rounded-md font-medium tracking-tight",
        "transition-colors focus-ring disabled:cursor-not-allowed",
        VARIANTS[variant],
        SIZES[size],
        className,
      )}
    >
      {leading}
      {children}
    </button>
  );
}
