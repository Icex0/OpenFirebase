import * as RSelect from "@radix-ui/react-select";

import { cn } from "@/lib/cn";

export interface SelectOption {
  value: string;
  label: string;
}

interface SelectProps {
  value: string;
  onValueChange: (v: string) => void;
  options: SelectOption[];
  placeholder?: string;
  active?: boolean;
  className?: string;
  triggerClassName?: string;
}

export function Select({
  value,
  onValueChange,
  options,
  placeholder,
  active = false,
  className,
  triggerClassName,
}: SelectProps) {
  return (
    <div className={className}>
      <RSelect.Root value={value} onValueChange={onValueChange}>
        <RSelect.Trigger
          className={cn(
            "group inline-flex w-full items-center justify-between gap-2 rounded-md border bg-ink-950/60 px-2.5 py-1.5 font-mono text-xs transition-colors focus:outline-none focus:ring-1 focus:ring-accent/60 focus:border-accent",
            active
              ? "border-accent/60 text-ink-100"
              : "border-ink-700 text-ink-300 hover:border-ink-600 hover:text-ink-100",
            triggerClassName,
          )}
        >
          <RSelect.Value placeholder={placeholder} />
          <RSelect.Icon className="text-ink-500 transition-transform group-data-[state=open]:rotate-180">
            <ChevronDown />
          </RSelect.Icon>
        </RSelect.Trigger>
        <RSelect.Portal>
          <RSelect.Content
            position="popper"
            sideOffset={6}
            className={cn(
              "z-50 min-w-[var(--radix-select-trigger-width)] overflow-hidden rounded-md border border-ink-700/80 bg-ink-900/95 shadow-xl shadow-black/40 backdrop-blur-sm",
              "data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=open]:zoom-in-95 data-[state=closed]:zoom-out-95",
            )}
          >
            <RSelect.Viewport className="max-h-[320px] p-1">
              {options.map((o) => (
                <RSelect.Item
                  key={o.value}
                  value={o.value}
                  className={cn(
                    "relative flex cursor-pointer select-none items-center gap-2 rounded-sm px-2 py-1.5 pl-7 pr-3 font-mono text-xs text-ink-200 outline-none",
                    "data-[highlighted]:bg-ink-800 data-[highlighted]:text-ink-50",
                    "data-[state=checked]:text-accent",
                  )}
                >
                  <RSelect.ItemIndicator className="absolute left-2 inline-flex items-center">
                    <Check />
                  </RSelect.ItemIndicator>
                  <RSelect.ItemText>{o.label}</RSelect.ItemText>
                </RSelect.Item>
              ))}
            </RSelect.Viewport>
          </RSelect.Content>
        </RSelect.Portal>
      </RSelect.Root>
    </div>
  );
}

function ChevronDown() {
  return (
    <svg
      width="10"
      height="10"
      viewBox="0 0 10 10"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <path d="M2 4l3 3 3-3" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Check() {
  return (
    <svg
      width="11"
      height="11"
      viewBox="0 0 11 11"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden
    >
      <path d="M2 5.5l2.5 2.5L9 3" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
