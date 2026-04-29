import { useEffect } from "react";

import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";

interface Props {
  open: boolean;
  filename: string;
  loading?: boolean;
  onCancel: () => void;
  onSame: () => void;
  onChange: () => void;
}

export function RescanDialog({
  open,
  filename,
  loading,
  onCancel,
  onSame,
  onChange,
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
      <div onClick={onCancel} className="absolute inset-0 bg-black/50" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Rescan"
        className={cn(
          "relative w-full max-w-md rounded-lg border border-ink-700/80 bg-ink-950 shadow-2xl transition-transform",
          open ? "scale-100" : "scale-95",
        )}
      >
        <div className="px-5 pb-4 pt-5">
          <h2 className="text-base font-semibold text-ink-100">Rescan</h2>
          <p className="mt-2 text-sm text-ink-300">
            Run another scan against{" "}
            <span className="font-mono text-ink-100">{filename}</span>?
          </p>
          <p className="mt-2 text-xs text-ink-400">
            Use the same settings as before, or open the configuration screen
            prefilled with them so you can tweak before re-running.
          </p>
        </div>
        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-ink-700/60 bg-ink-900/40 px-4 py-3">
          <Button size="sm" variant="ghost" onClick={onCancel} disabled={loading}>
            Cancel
          </Button>
          <Button size="sm" variant="ghost" onClick={onChange} disabled={loading}>
            Change settings…
          </Button>
          <Button size="sm" autoFocus onClick={onSame} disabled={loading}>
            {loading ? "Working…" : "Run with same settings"}
          </Button>
        </div>
      </div>
    </div>
  );
}
