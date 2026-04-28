import { useEffect } from "react";

import { VerdictDot } from "@/components/ui/VerdictDot";
import { cn } from "@/lib/cn";
import type { Finding, ProbeResult } from "@/lib/types";

const SERVICE_LABEL: Record<Finding["service"], string> = {
  rtdb: "RTDB",
  firestore: "Firestore",
  storage: "Storage",
  remote_config: "Remote Config",
  cloud_functions: "Cloud Functions",
};

interface Props {
  finding: Finding | null;
  onClose: () => void;
}

export function FindingDetailDrawer({ finding, onClose }: Props) {
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
              <ProbeBlock label="Unauthenticated" probe={finding.unauth} />
              {finding.auth && (
                <ProbeBlock label="Authenticated" probe={finding.auth} subdued />
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
  label,
  probe,
  subdued,
}: {
  label: string;
  probe: ProbeResult;
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
      <ResponseBody body={probe.response_content} />
    </Section>
  );
}

function ResponseBody({ body }: { body?: string | null }) {
  if (!body) return null;
  // Pretty-print JSON if it parses; otherwise show raw text.
  let pretty = body;
  try {
    const parsed = JSON.parse(body);
    pretty = JSON.stringify(parsed, null, 2);
  } catch {
    /* not JSON, fine */
  }
  return (
    <div className="mt-2">
      <div className="mb-1 font-mono text-[10px] uppercase tracking-wider text-ink-500">
        Response body
      </div>
      <pre className="max-h-[40vh] overflow-auto whitespace-pre-wrap break-words rounded border border-ink-700/60 bg-ink-900/40 px-3 py-2 font-mono text-[11px] text-ink-200">
        {pretty}
      </pre>
    </div>
  );
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
