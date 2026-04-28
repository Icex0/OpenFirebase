import { useMemo, useState } from "react";

import { VerdictDot } from "@/components/ui/VerdictDot";
import { cn } from "@/lib/cn";
import type { Finding, Verdict } from "@/lib/types";
import { VERDICT_PRIORITY } from "@/lib/verdict";

import { FindingDetailDrawer } from "./FindingDetailDrawer";

const SERVICE_LABEL: Record<Finding["service"], string> = {
  rtdb: "RTDB",
  firestore: "Firestore",
  storage: "Storage",
  remote_config: "Remote Config",
  cloud_functions: "Cloud Functions",
};

interface Props {
  findings: Finding[];
}

type Filter = Verdict | "all";
type SortKey = "service" | "probe" | "url" | "unauth" | "auth";
type SortDir = "asc" | "desc";

export function FindingsTable({ findings }: Props) {
  const [filter, setFilter] = useState<Filter>("all");
  const [sortKey, setSortKey] = useState<SortKey>("unauth");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const [active, setActive] = useState<Finding | null>(null);

  const visible = useMemo(() => {
    const filtered = filter === "all" ? findings : findings.filter((f) => f.unauth.verdict === filter);
    const arr = [...filtered].sort((a, b) => cmpFindings(a, b, sortKey));
    if (sortDir === "desc") arr.reverse();
    return arr;
  }, [findings, filter, sortKey, sortDir]);

  const toggleSort = (k: SortKey) => {
    if (k === sortKey) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else {
      setSortKey(k);
      setSortDir("asc");
    }
  };

  const counts = useMemo(() => {
    const map = new Map<Verdict, number>();
    for (const f of findings) {
      map.set(f.unauth.verdict, (map.get(f.unauth.verdict) ?? 0) + 1);
    }
    return map;
  }, [findings]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-1.5">
        <FilterChip active={filter === "all"} onClick={() => setFilter("all")}>
          All <span className="text-ink-400">· {findings.length}</span>
        </FilterChip>
        {Array.from(counts.entries())
          .sort((a, b) => VERDICT_PRIORITY[a[0]] - VERDICT_PRIORITY[b[0]])
          .map(([verdict, count]) => (
            <FilterChip
              key={verdict}
              active={filter === verdict}
              onClick={() => setFilter(verdict)}
            >
              <VerdictDot verdict={verdict} subdued />
              <span className="ml-1 text-ink-400">· {count}</span>
            </FilterChip>
          ))}
      </div>

      <div className="overflow-x-auto rounded-lg border border-ink-700/80">
        <table className="w-full border-collapse text-sm">
          <thead className="bg-ink-900/80 text-left">
            <tr className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
              <SortTh label="Service" k="service" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
              <SortTh label="Probe" k="probe" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
              <SortTh label="URL" k="url" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
              <SortTh label="Unauth" k="unauth" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
              <SortTh label="Auth" k="auth" sortKey={sortKey} sortDir={sortDir} onClick={toggleSort} />
            </tr>
          </thead>
          <tbody>
            {visible.map((f, i) => (
              <tr
                key={f.id}
                onClick={() => setActive(f)}
                className={cn(
                  "cursor-pointer border-t border-ink-700/60 transition-colors hover:bg-ink-800/40",
                  i % 2 === 1 && "bg-ink-900/20",
                  active?.id === f.id && "bg-accent-muted/30",
                )}
              >
                <Td className="whitespace-nowrap text-ink-200">
                  {SERVICE_LABEL[f.service]}
                </Td>
                <Td className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
                  {f.probe}
                </Td>
                <Td className="font-mono text-xs text-ink-200">
                  <div className="max-w-[28rem] truncate" title={f.url}>
                    {f.url}
                  </div>
                </Td>
                <Td>
                  <div className="flex items-center gap-2">
                    <VerdictDot verdict={f.unauth.verdict} />
                    {f.unauth.status && (
                      <span className="font-mono text-[11px] text-ink-400">
                        {f.unauth.status}
                      </span>
                    )}
                  </div>
                </Td>
                <Td>
                  {f.auth ? (
                    <div className="flex items-center gap-2">
                      <VerdictDot verdict={f.auth.verdict} subdued />
                      {f.auth.status && (
                        <span className="font-mono text-[11px] text-ink-400">
                          {f.auth.status}
                        </span>
                      )}
                    </div>
                  ) : (
                    <span className="font-mono text-[11px] text-ink-500">—</span>
                  )}
                </Td>
              </tr>
            ))}
            {visible.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-10 text-center text-sm text-ink-400">
                  No findings in this view.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <FindingDetailDrawer finding={active} onClose={() => setActive(null)} />
    </div>
  );
}

function cmpFindings(a: Finding, b: Finding, key: SortKey): number {
  switch (key) {
    case "service":
      return SERVICE_LABEL[a.service].localeCompare(SERVICE_LABEL[b.service]);
    case "probe":
      return a.probe.localeCompare(b.probe);
    case "url":
      return a.url.localeCompare(b.url);
    case "unauth":
      return VERDICT_PRIORITY[a.unauth.verdict] - VERDICT_PRIORITY[b.unauth.verdict];
    case "auth": {
      const av = a.auth ? VERDICT_PRIORITY[a.auth.verdict] : 999;
      const bv = b.auth ? VERDICT_PRIORITY[b.auth.verdict] : 999;
      return av - bv;
    }
  }
}

interface SortThProps {
  label: string;
  k: SortKey;
  sortKey: SortKey;
  sortDir: SortDir;
  onClick: (k: SortKey) => void;
}

function SortTh({ label, k, sortKey, sortDir, onClick }: SortThProps) {
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

function Td({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return <td className={cn("px-4 py-2.5 align-top", className)}>{children}</td>;
}

function FilterChip({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs transition-colors",
        active
          ? "border-accent/60 bg-accent-muted/50 text-ink-100"
          : "border-ink-700 bg-ink-900/40 text-ink-300 hover:border-ink-600",
      )}
    >
      {children}
    </button>
  );
}
