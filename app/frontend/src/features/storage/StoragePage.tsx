import { useState } from "react";
import { Link } from "react-router-dom";

import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { cn } from "@/lib/cn";

import type { StoredBlob } from "./api";
import { useDeleteStoredBlob, useStoredBundles } from "./hooks";

export function StoragePage() {
  const { data, isLoading, error } = useStoredBundles();
  const del = useDeleteStoredBlob();
  const [pending, setPending] = useState<StoredBlob | null>(null);

  const totalBytes = (data ?? []).reduce((acc, b) => acc + b.size, 0);

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Storage</h1>
        <p className="mt-1 text-sm text-ink-400">
          Uploaded bundles are stored once per unique file (content-addressed by
          SHA-256). Rescanning doesn't duplicate bytes — the same blob is reused
          across scans. Deleting a blob removes it from every scan that references
          it; findings stay, but rescan will no longer work for those scans.
        </p>
      </div>

      {isLoading && <p className="text-sm text-ink-400">Loading…</p>}
      {error && <p className="text-sm text-severity-public">Failed to load storage.</p>}

      {data && data.length === 0 && (
        <div className="rounded-lg border border-dashed border-ink-700 bg-ink-900/30 px-6 py-16 text-center">
          <p className="text-sm text-ink-300">No bundles stored.</p>
        </div>
      )}

      {data && data.length > 0 && (
        <>
          <p className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
            {data.length} unique blob{data.length === 1 ? "" : "s"} ·{" "}
            {formatBytes(totalBytes)} on disk
          </p>
          <div className="overflow-hidden rounded-lg border border-ink-700/80">
            <table className="w-full text-sm">
              <thead className="bg-ink-900/60 text-left font-mono text-[11px] uppercase tracking-wider text-ink-400">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Filename(s)</th>
                  <th className="px-4 py-2.5 font-medium">SHA-256</th>
                  <th className="px-4 py-2.5 font-medium">Size</th>
                  <th className="px-4 py-2.5 font-medium">Used by</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {data.map((b, i) => (
                  <tr
                    key={b.sha256}
                    className={cn(
                      "border-t border-ink-700/60 align-top",
                      i % 2 === 1 && "bg-ink-900/20",
                    )}
                  >
                    <td className="px-4 py-3 font-mono text-[11px] text-ink-100">
                      {b.filenames.join(", ")}
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-ink-400">
                      {b.sha256.slice(0, 12)}…
                    </td>
                    <td className="px-4 py-3 font-mono text-[11px] text-ink-300">
                      {formatBytes(b.size)}
                    </td>
                    <td className="px-4 py-3 text-[11px] text-ink-300">
                      <div className="flex flex-col gap-0.5">
                        {b.scans.map((s) => (
                          <Link
                            key={s.scan_id}
                            to={`/scans/${s.scan_id}`}
                            className="group flex items-baseline gap-2 font-mono hover:text-accent"
                          >
                            <span className="text-ink-200 group-hover:text-accent">
                              {s.scan_filename}
                            </span>
                            <span className="text-[10px] tabular-nums text-ink-500">
                              {new Date(s.created_at).toLocaleString("en-GB")}
                            </span>
                          </Link>
                        ))}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setPending(b)}
                      >
                        Delete
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <ConfirmDialog
        open={pending !== null}
        title="Delete stored blob?"
        description={
          pending ? (
            <>
              This will free{" "}
              <span className="font-mono text-ink-100">{formatBytes(pending.size)}</span>{" "}
              and remove the blob from{" "}
              <span className="font-mono text-ink-100">
                {pending.scans.length} scan{pending.scans.length === 1 ? "" : "s"}
              </span>
              . Findings remain, but rescan will no longer work for those scans.
            </>
          ) : null
        }
        confirmLabel="Delete blob"
        destructive
        loading={del.isPending}
        onCancel={() => setPending(null)}
        onConfirm={() => {
          if (!pending) return;
          del.mutate(pending.sha256, { onSettled: () => setPending(null) });
        }}
      />
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
