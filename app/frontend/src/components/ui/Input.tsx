import { forwardRef, type InputHTMLAttributes } from "react";
import { cn } from "@/lib/cn";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(
  function Input({ className, ...rest }, ref) {
    return (
      <input
        ref={ref}
        {...rest}
        className={cn(
          "h-9 w-full rounded-md border border-ink-700 bg-ink-900/60 px-3 text-sm",
          "text-ink-100 placeholder:text-ink-400 focus-ring",
          "transition-colors hover:border-ink-600 focus:border-accent/60",
          className,
        )}
      />
    );
  },
);
