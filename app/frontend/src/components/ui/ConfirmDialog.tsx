import { useEffect } from "react";

import { cn } from "@/lib/cn";

import { Button } from "./Button";

interface Props {
  open: boolean;
  title: string;
  description?: React.ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  destructive?: boolean;
  loading?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel = "Confirm",
  cancelLabel = "Cancel",
  destructive,
  loading,
  onConfirm,
  onCancel,
}: Props) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onCancel]);

  return (
    <div
      className={cn(
        "fixed inset-0 z-50 flex items-center justify-center p-4 transition-opacity",
        open ? "opacity-100" : "pointer-events-none opacity-0",
      )}
      aria-hidden={!open}
    >
      <div
        onClick={onCancel}
        className="absolute inset-0 bg-black/50"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        className={cn(
          "relative w-full max-w-md rounded-lg border border-ink-700/80 bg-ink-950 shadow-2xl transition-transform",
          open ? "scale-100" : "scale-95",
        )}
      >
        <div className="px-5 pb-4 pt-5">
          <h2 className="text-base font-semibold text-ink-100">{title}</h2>
          {description && (
            <div className="mt-2 text-sm text-ink-300">{description}</div>
          )}
        </div>
        <div className="flex items-center justify-end gap-2 border-t border-ink-700/60 bg-ink-900/40 px-4 py-3">
          <Button size="sm" variant="ghost" onClick={onCancel} disabled={loading}>
            {cancelLabel}
          </Button>
          <Button
            autoFocus
            size="sm"
            variant={destructive ? "danger" : undefined}
            onClick={onConfirm}
            disabled={loading}
          >
            {loading ? "Working…" : confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
