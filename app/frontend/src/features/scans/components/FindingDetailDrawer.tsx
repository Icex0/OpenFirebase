import { useEffect, useMemo, useRef, useState } from "react";

import { VerdictDot } from "@/components/ui/VerdictDot";
import { cn } from "@/lib/cn";
import type { Finding, ProbeResult } from "@/lib/types";

import { useFindingBody } from "../hooks";

const SERVICE_LABEL: Record<Finding["service"], string> = {
  rtdb: "RTDB",
  firestore: "Firestore",
  storage: "Storage",
  remote_config: "Remote Config",
  cloud_functions: "Cloud Functions",
};

interface Props {
  scanId: string;
  finding: Finding | null;
  onClose: () => void;
}

export function FindingDetailDrawer({ scanId, finding, onClose }: Props) {
  // Esc closes the drawer.
  useEffect(() => {
    if (!finding) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [finding, onClose]);

  const open = finding !== null;

  return (
    <>
      <div
        onClick={onClose}
        className={cn(
          "fixed inset-0 z-40 bg-black/40 transition-opacity",
          open ? "opacity-100" : "pointer-events-none opacity-0",
        )}
      />
      <aside
        className={cn(
          "fixed right-0 top-0 z-50 flex h-full w-full max-w-xl flex-col border-l border-ink-700/80 bg-ink-950 shadow-2xl transition-transform",
          open ? "translate-x-0" : "translate-x-full",
        )}
      >
        {finding && (
          <>
            <header className="flex items-start justify-between gap-3 border-b border-ink-700/60 bg-ink-900/60 px-5 py-4">
              <div className="min-w-0">
                <div className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
                  {SERVICE_LABEL[finding.service]} · {finding.probe}
                </div>
                <div className="mt-1 break-all font-mono text-xs text-ink-100">
                  {finding.url}
                </div>
              </div>
              <button
                type="button"
                onClick={onClose}
                className="shrink-0 rounded p-1 font-mono text-sm text-ink-400 hover:bg-ink-800/60 hover:text-ink-100"
                aria-label="Close"
              >
                ✕
              </button>
            </header>

            <div className="flex-1 overflow-y-auto px-5 py-4 text-sm">
              <ProbeBlock
                scanId={scanId}
                kind="unauth"
                label="Unauthenticated"
                probe={finding.unauth}
                finding={finding}
              />
              {finding.auth && (
                <ProbeBlock
                  scanId={scanId}
                  kind="auth"
                  label="Authenticated"
                  probe={finding.auth}
                  finding={finding}
                  subdued
                />
              )}
              {finding.resource && Object.keys(finding.resource).length > 0 && (
                <Section title="Resource">
                  <ResourceView resource={finding.resource} />
                </Section>
              )}
            </div>
          </>
        )}
      </aside>
    </>
  );
}

function ProbeBlock({
  scanId,
  kind,
  label,
  probe,
  finding,
  subdued,
}: {
  scanId: string;
  kind: "unauth" | "auth";
  label: string;
  probe: ProbeResult;
  finding: Finding;
  subdued?: boolean;
}) {
  return (
    <Section title={label}>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs">
        <Field label="Verdict">
          <VerdictDot verdict={probe.verdict} subdued={subdued} />
        </Field>
        <Field label="Status">
          <span className="font-mono text-ink-200">{probe.status || "—"}</span>
        </Field>
        {probe.identity && (probe.identity.kind || probe.identity.ref) && (
          <Field label="Identity">
            <span className="font-mono text-ink-200">
              {probe.identity.kind ?? "?"}
              {probe.identity.ref ? ` · ${probe.identity.ref}` : ""}
            </span>
          </Field>
        )}
      </div>
      {probe.message && (
        <pre className="mt-2 max-h-40 overflow-auto whitespace-pre-wrap break-words rounded border border-ink-700/60 bg-ink-900/40 px-3 py-2 font-mono text-[11px] text-ink-300">
          {probe.message}
        </pre>
      )}
      {probe.has_body && (
        <ResponseBody
          scanId={scanId}
          findingId={finding.id}
          probeKind={kind}
          filename={buildResponseFilename(finding, label)}
        />
      )}
    </Section>
  );
}

function buildResponseFilename(finding: Finding, label: string): string {
  const which = label.toLowerCase().startsWith("auth") ? "auth" : "unauth";
  const slug = finding.url.replace(/^https?:\/\//, "").replace(/[^A-Za-z0-9.-]+/g, "_").slice(0, 80);
  return `response-${finding.service}-${finding.probe}-${which}-${slug || "body"}.txt`;
}

function ResponseBody({
  scanId,
  findingId,
  probeKind,
  filename,
}: {
  scanId: string;
  findingId: string;
  probeKind: "unauth" | "auth";
  filename: string;
}) {
  const { data, isLoading, error } = useFindingBody(
    scanId,
    findingId,
    probeKind,
    true,
  );
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const [copied, setCopied] = useState(false);
  const matchRefs = useRef<(HTMLElement | null)[]>([]);

  const body = data?.content ?? "";

  const pretty = useMemo(() => {
    if (!body) return "";
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  }, [body]);

  const matchCount = useMemo(() => {
    const q = query.trim();
    if (!q || !pretty) return 0;
    return pretty.toLowerCase().split(q.toLowerCase()).length - 1;
  }, [pretty, query]);

  // Reset active index when the search query or body changes; clamp it if
  // matches shrink below the current cursor.
  useEffect(() => {
    setActive(0);
  }, [query, pretty]);

  // Scroll the active match into view whenever it (or the match set) changes.
  useEffect(() => {
    if (matchCount === 0) return;
    const el = matchRefs.current[active];
    if (el) el.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [active, matchCount, query, pretty]);

  const goNext = () => {
    if (matchCount === 0) return;
    setActive((i) => (i + 1) % matchCount);
  };
  const goPrev = () => {
    if (matchCount === 0) return;
    setActive((i) => (i - 1 + matchCount) % matchCount);
  };

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(pretty);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* ignore */
    }
  };

  const handleDownload = () => {
    const blob = new Blob([pretty], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const ready = !isLoading && !error && Boolean(pretty);

  return (
    <div className="mt-2">
      <div className="mb-1.5 flex items-center justify-between gap-2">
        <div className="font-mono text-[10px] uppercase tracking-wider text-ink-500">
          Response body
          {data?.truncated && (
            <span className="ml-2 normal-case text-ink-400">
              (truncated)
            </span>
          )}
        </div>
        <button
          type="button"
          onClick={handleDownload}
          disabled={!ready}
          className="rounded border border-ink-700/60 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-ink-300 hover:border-ink-500 hover:text-ink-100 disabled:opacity-40 disabled:hover:border-ink-700/60 disabled:hover:text-ink-300"
        >
          Download
        </button>
      </div>
      <div className="mb-1.5 flex items-center gap-2 rounded-md border border-ink-700 bg-ink-950/60 px-2.5 py-1 focus-within:border-ink-500">
        <input
          type="search"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              if (e.shiftKey) goPrev();
              else goNext();
            }
          }}
          placeholder="Search in response body…"
          className="flex-1 bg-transparent font-mono text-[11px] text-ink-100 placeholder:text-ink-500 focus:outline-none"
        />
        {query.trim() && (
          <span className="shrink-0 font-mono text-[10px] uppercase tracking-wider tabular-nums text-ink-400">
            {matchCount === 0 ? "0" : `${active + 1} / ${matchCount}`}
          </span>
        )}
        <button
          type="button"
          onClick={goPrev}
          disabled={matchCount === 0}
          aria-label="Previous match"
          className="shrink-0 rounded px-1.5 py-0.5 font-mono text-[11px] text-ink-300 hover:bg-ink-800/60 hover:text-ink-100 disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-ink-300"
        >
          ↑
        </button>
        <button
          type="button"
          onClick={goNext}
          disabled={matchCount === 0}
          aria-label="Next match"
          className="shrink-0 rounded px-1.5 py-0.5 font-mono text-[11px] text-ink-300 hover:bg-ink-800/60 hover:text-ink-100 disabled:opacity-40 disabled:hover:bg-transparent disabled:hover:text-ink-300"
        >
          ↓
        </button>
      </div>
      <div className="relative">
        {ready && (
          <button
            type="button"
            onClick={handleCopy}
            className="absolute right-1.5 top-1.5 z-10 rounded border border-ink-700/60 bg-ink-900/80 px-2 py-0.5 font-mono text-[10px] uppercase tracking-wider text-ink-300 backdrop-blur hover:border-ink-500 hover:text-ink-100"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        )}
        <pre className="max-h-[40vh] min-h-[2.5rem] overflow-auto whitespace-pre-wrap break-words rounded border border-ink-700/60 bg-ink-900/40 px-3 py-2 pr-16 font-mono text-[11px] text-ink-200">
          {isLoading && (
            <span className="text-ink-500">Loading response body…</span>
          )}
          {!isLoading && error && (
            <span className="text-severity-public">Failed to load response body.</span>
          )}
          {ready &&
            (query.trim()
              ? highlightMatches(pretty, query.trim(), active, matchRefs)
              : pretty)}
        </pre>
      </div>
    </div>
  );
}

function highlightMatches(
  text: string,
  query: string,
  activeIndex: number,
  refs: React.MutableRefObject<(HTMLElement | null)[]>,
): React.ReactNode {
  if (!query) return text;
  refs.current = [];
  const lower = text.toLowerCase();
  const q = query.toLowerCase();
  const out: React.ReactNode[] = [];
  let i = 0;
  let matchIdx = 0;
  let key = 0;
  while (i < text.length) {
    const idx = lower.indexOf(q, i);
    if (idx === -1) {
      out.push(text.slice(i));
      break;
    }
    if (idx > i) out.push(text.slice(i, idx));
    const isActive = matchIdx === activeIndex;
    const captured = matchIdx;
    out.push(
      <mark
        key={key++}
        ref={(el) => {
          refs.current[captured] = el;
        }}
        className={cn(
          "rounded-sm px-0.5",
          isActive
            ? "bg-accent text-ink-950"
            : "bg-accent/40 text-ink-100",
        )}
      >
        {text.slice(idx, idx + query.length)}
      </mark>,
    );
    matchIdx++;
    i = idx + query.length;
  }
  return out;
}

function ResourceView({ resource }: { resource: Record<string, unknown> | null }) {
  if (!resource || Object.keys(resource).length === 0) return null;
  return (
    <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-xs">
      {Object.entries(resource).map(([k, v]) => (
        <ResourceRow key={k} label={k} value={v} />
      ))}
    </dl>
  );
}

function ResourceRow({ label, value }: { label: string; value: unknown }) {
  return (
    <>
      <dt className="font-mono text-[11px] uppercase tracking-wider text-ink-500">
        {label.replace(/_/g, " ")}
      </dt>
      <dd className="break-words font-mono text-[12px] text-ink-200">
        {renderValue(value)}
      </dd>
    </>
  );
}

function renderValue(v: unknown): React.ReactNode {
  if (v === null || v === undefined) return <span className="text-ink-500">—</span>;
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") {
    return String(v);
  }
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="text-ink-500">—</span>;
    return (
      <ul className="space-y-0.5">
        {v.map((item, i) => (
          <li key={i}>{renderValue(item)}</li>
        ))}
      </ul>
    );
  }
  // Nested object — render compact key: value.
  return (
    <ul className="space-y-0.5">
      {Object.entries(v as Record<string, unknown>).map(([k, val]) => (
        <li key={k}>
          <span className="text-ink-500">{k}:</span> {renderValue(val)}
        </li>
      ))}
    </ul>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-5">
      <h3 className="mb-2 font-mono text-[10px] uppercase tracking-wider text-ink-400">
        {title}
      </h3>
      {children}
    </section>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="font-mono text-[10px] uppercase tracking-wider text-ink-500">
        {label}
      </span>
      {children}
    </div>
  );
}
