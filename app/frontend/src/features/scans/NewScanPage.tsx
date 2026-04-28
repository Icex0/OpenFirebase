import { Link } from "react-router-dom";

import { cn } from "@/lib/cn";

export function NewScanPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">New scan</h1>
        <p className="mt-1 text-sm text-ink-400">
          Pick how you want to feed Firebase identifiers into the scanner.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <ModeTile
          to="/scans/new/bundle"
          title="APK / IPA"
          description="Upload one or more APK / IPA files. The scanner extracts Firebase project IDs and config automatically before scanning."
          tag="--app-dir"
        />
        <ModeTile
          to="/scans/new/manual"
          title="Manual"
          description="Already have project IDs (and optionally api keys, app IDs, etc.) from web recon? Paste them in directly. Useful for testing a single project or when scanning multiple projects."
          tag="--project-id"
        />
      </div>
    </div>
  );
}

function ModeTile({
  to,
  title,
  description,
  tag,
}: {
  to: string;
  title: string;
  description: string;
  tag: string;
}) {
  return (
    <Link
      to={to}
      className={cn(
        "group flex flex-col gap-2 rounded-lg border border-ink-700/80 bg-ink-900/40 p-5",
        "transition-colors hover:border-accent/60 hover:bg-ink-900/60",
      )}
    >
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-base font-semibold text-ink-100">{title}</h2>
        <span className="font-mono text-[10px] uppercase tracking-wider text-ink-500 group-hover:text-accent">
          {tag}
        </span>
      </div>
      <p className="text-xs text-ink-400">{description}</p>
    </Link>
  );
}
