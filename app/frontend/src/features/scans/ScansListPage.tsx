import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import { StatusPill } from "@/components/ui/StatusPill";
import { Tooltip } from "@/components/ui/Tooltip";

import { ScanSettingsButton } from "./components/ScanSettingsButton";
import { cn } from "@/lib/cn";
import type { ScanSummary } from "@/lib/types";

import { scanSubjects } from "./defaults";
import { useDeleteScan, useRescanScan, useScans } from "./hooks";

type SortKey = "filename" | "status" | "started" | "duration";
type SortDir = "asc" | "desc";

export function ScansListPage() {
  const { data, isLoading, error } = useScans();
  const del = useDeleteScan();
  const rescan = useRescanScan();
  const navigate = useNavigate();
  const [pendingDelete, setPendingDelete] = useState<ScanSummary | null>(null);
  const [sortKey, setSortKey] = useState<SortKey>("started");
  const [sortDir, setSortDir] = useState<SortDir>("desc");

  const sorted = useMemo(() => {
    if (!data) return data;
    const arr = [...data];
    arr.sort((a, b) => cmpScans(a, b, sortKey));
    if (sortDir === "desc") arr.reverse();
    return arr;
  }, [data, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (key === sortKey) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir(key === "started" || key === "duration" ? "desc" : "asc");
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-end justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Scans</h1>
          <p className="mt-1 text-sm text-ink-400">
            History of Firebase security scans you have run.
          </p>
        </div>
        <Link to="/scans/new">
          <Button>New scan</Button>
        </Link>
      </div>

      {isLoading && <p className="text-sm text-ink-400">Loading…</p>}
      {error && <p className="text-sm text-severity-public">Failed to load scans.</p>}

      {data && data.length === 0 && (
        <div className="rounded-lg border border-dashed border-ink-700 bg-ink-900/30 px-6 py-16 text-center">
          <p className="text-sm text-ink-300">No scans yet.</p>
          <Link to="/scans/new" className="mt-3 inline-block text-sm text-accent hover:text-accent-hover">
            Upload your first APK/IPA →
          </Link>
        </div>
      )}

      {data && data.length > 0 && (
        <div className="overflow-hidden rounded-lg border border-ink-700/80">
          <table className="w-full text-sm">
            <thead className="bg-ink-900/60 text-left font-mono text-[11px] uppercase tracking-wider text-ink-400">
              <tr>
                <SortHeader label="File" k="filename" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
                <SortHeader label="Status" k="status" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
                <SortHeader label="Started" k="started" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
                <SortHeader label="Duration" k="duration" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {sorted!.map((s, i) => (
                <tr
                  key={s.id}
                  onClick={() => navigate(`/scans/${s.id}`)}
                  className={cn(
                    "cursor-pointer border-t border-ink-700/60 transition-colors hover:bg-ink-800/30",
                    i % 2 === 1 && "bg-ink-900/20",
                  )}
                >
                  <td className="px-4 py-3">
                    <BundleName filename={s.filename} scan={s} />
                  </td>
                  <td className="px-4 py-3">
                    <StatusPill status={s.status} />
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-ink-300">
                    {formatDate(s.started_at ?? s.created_at)}
                  </td>
                  <td className="px-4 py-3 font-mono text-[11px] text-ink-300">
                    {formatDuration(s.started_at, s.finished_at)}
                  </td>
                  <td
                    className="px-4 py-3 text-right"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="inline-flex items-center gap-1">
                      <ScanSettingsButton options={s.options} size="sm" iconOnly />
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={
                          rescan.isPending ||
                          s.status === "queued" ||
                          s.status === "running"
                        }
                        onClick={() =>
                          rescan.mutate(s.id, {
                            onSuccess: (next) => navigate(`/scans/${next.id}`),
                          })
                        }
                      >
                        Rescan
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => setPendingDelete(s)}
                      >
                        Delete
                      </Button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <ConfirmDialog
        open={pendingDelete !== null}
        title="Delete scan?"
        description={
          pendingDelete ? (
            <>
              This will permanently remove{" "}
              <span className="font-mono text-ink-100">{pendingDelete.filename}</span>{" "}
              and all of its findings.
            </>
          ) : null
        }
        confirmLabel="Delete"
        destructive
        loading={del.isPending}
        onCancel={() => setPendingDelete(null)}
        onConfirm={() => {
          if (!pendingDelete) return;
          const id = pendingDelete.id;
          del.mutate(id, {
            onSettled: () => setPendingDelete(null),
          });
        }}
      />
    </div>
  );
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString("en-GB");
}

function formatDuration(start: string | null, end: string | null): string {
  if (!start) return "—";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const ms = Math.max(0, e - s);
  const sec = Math.round(ms / 1000);
  if (sec < 60) return `${sec}s`;
  return `${Math.floor(sec / 60)}m ${sec % 60}s`;
}

const STATUS_RANK: Record<string, number> = {
  running: 0,
  queued: 1,
  failed: 2,
  done: 3,
};

function startedTime(s: ScanSummary): number {
  const v = s.started_at ?? s.created_at;
  return v ? new Date(v).getTime() : 0;
}

function durationMs(s: ScanSummary): number {
  if (!s.started_at) return -1;
  const start = new Date(s.started_at).getTime();
  const end = s.finished_at ? new Date(s.finished_at).getTime() : Date.now();
  return Math.max(0, end - start);
}

function cmpScans(a: ScanSummary, b: ScanSummary, key: SortKey): number {
  switch (key) {
    case "filename":
      return a.filename.localeCompare(b.filename);
    case "status":
      return (STATUS_RANK[a.status] ?? 99) - (STATUS_RANK[b.status] ?? 99);
    case "started":
      return startedTime(a) - startedTime(b);
    case "duration":
      return durationMs(a) - durationMs(b);
  }
}

interface SortHeaderProps {
  label: string;
  k: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
  onClick: (k: SortKey) => void;
}

function BundleName({ filename, scan }: { filename: string; scan: ScanSummary }) {
  // Show a hover tooltip with the full list when a scan covers multiple
  // bundles (APK/IPA upload) or multiple project IDs (manual mode).
  const { kind, items } = scanSubjects(scan);
  if (items.length <= 1) {
    return <span className="font-mono text-xs text-ink-100">{filename}</span>;
  }
  const label = kind === "bundle" ? "bundle" : "project";
  return (
    <Tooltip
      side="bottom"
      align="start"
      content={
        <div className="space-y-2">
          <div className="font-mono text-[10px] uppercase tracking-wider text-ink-400">
            {items.length} {label}{items.length === 1 ? "" : "s"}
          </div>
          <ul className="max-h-[280px] space-y-0.5 overflow-y-auto pr-1 font-mono text-[11px] text-ink-200">
            {items.map((b, i) => (
              <li key={`${b}-${i}`} className="flex items-baseline gap-2">
                <span className="w-5 shrink-0 text-right text-[10px] text-ink-500 tabular-nums">
                  {i + 1}
                </span>
                <span className="truncate">{b}</span>
              </li>
            ))}
          </ul>
        </div>
      }
    >
      <span className="cursor-help font-mono text-xs text-ink-100 underline decoration-ink-600/60 decoration-dotted underline-offset-4 hover:decoration-accent/60">
        {filename}
      </span>
    </Tooltip>
  );
}

function SortHeader({ label, k, sortKey, sortDir, onClick }: SortHeaderProps) {
  const active = sortKey === k;
  return (
    <th className="px-4 py-2.5 font-medium">
      <button
        type="button"
        onClick={() => onClick(k)}
        className={cn(
          "inline-flex items-center gap-1 uppercase tracking-wider transition-colors",
          active ? "text-ink-100" : "text-ink-400 hover:text-ink-200",
        )}
      >
        {label}
        <span className="text-[9px]">
          {active ? (sortDir === "asc" ? "▲" : "▼") : "↕"}
        </span>
      </button>
    </th>
  );
}
