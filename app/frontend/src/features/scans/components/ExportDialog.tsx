import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/Button";
import { cn } from "@/lib/cn";
import type { ScanDetail } from "@/lib/types";

import { downloadScan } from "../api";

interface Props {
  open: boolean;
  scan: ScanDetail | null;
  onClose: () => void;
}

// Field paths mirror docs/schema/openfirebase-scan.schema.json so the export
// stays a strict subset of the canonical scan document. Anything checked is
// kept; anything unchecked is dropped. Boilerplate fields the UI already
// surfaces (scan_id, timestamps, input.*, config, auth.identities,
// schema_version, tool_version, bundle path / signatures / etc.) aren't
// exposed here — they'd just clutter the picker.
type FieldId =
  // Scan timing
  | "started_at"
  | "finished_at"
  // Auth context
  | "auth.used"
  | "auth.identities"
  // ``extraction.bundles[]`` carries per-bundle structured fields:
  // ``service_accounts`` (paired client_email/private_key/project_id) and
  // ``leaked_private_keys`` (PEMs hardcoded in source). These never appear
  // in ``project.extracted_items`` — that pivot is unpaired strings only.
  | "extraction.bundles"
  // Summary
  | "summary.per_service"
  // Per project
  | "project.project_id"
  | "project.package_names"
  | "project.extracted_items"
  // Per finding
  | "finding.service"
  | "finding.url"
  | "finding.probe"
  | "finding.resource"
  | "finding.error"
  // Unauth probe
  | "unauth.status"
  | "unauth.security"
  | "unauth.verdict"
  | "unauth.message"
  | "unauth.response_content"
  // Auth probe
  | "auth_probe.status"
  | "auth_probe.security"
  | "auth_probe.verdict"
  | "auth_probe.message"
  | "auth_probe.response_content"
  | "auth_probe.identity";

interface FieldDef {
  id: FieldId;
  label: string;
  hint?: string;
}

interface Group {
  title: string;
  fields: FieldDef[];
}

const GROUPS: Group[] = [
  {
    title: "Scan",
    fields: [
      { id: "started_at", label: "started_at" },
      { id: "finished_at", label: "finished_at" },
      { id: "auth.used", label: "auth.used" },
      { id: "auth.identities", label: "auth.identities"},
      {
        id: "extraction.bundles",
        label: "extraction.bundles",
        hint: "Per-bundle service_accounts (paired) and leaked_private_keys.",
      },
      { id: "summary.per_service", label: "summary.per_service" },
    ],
  },
  {
    title: "Project",
    fields: [
      { id: "project.project_id", label: "project_id" },
      { id: "project.package_names", label: "package_names" },
      { id: "project.extracted_items", label: "extracted_items" },
    ],
  },
  {
    title: "Finding",
    fields: [
      { id: "finding.service", label: "service" },
      { id: "finding.url", label: "url" },
      { id: "finding.probe", label: "probe" },
      { id: "finding.resource", label: "resource" },
      { id: "finding.error", label: "error" },
    ],
  },
  {
    title: "Unauth probe",
    fields: [
      { id: "unauth.status", label: "status" },
      { id: "unauth.security", label: "security" },
      { id: "unauth.verdict", label: "verdict" },
      { id: "unauth.message", label: "message" },
      { id: "unauth.response_content", label: "response_content" },
    ],
  },
  {
    title: "Auth probe",
    fields: [
      { id: "auth_probe.status", label: "status" },
      { id: "auth_probe.security", label: "security" },
      { id: "auth_probe.verdict", label: "verdict" },
      { id: "auth_probe.message", label: "message" },
      { id: "auth_probe.response_content", label: "response_content" },
      { id: "auth_probe.identity", label: "identity" },
    ],
  },
];

const ALL_FIELDS: FieldId[] = GROUPS.flatMap((g) => g.fields.map((f) => f.id));

// Everything is on by default except the raw ``security`` strings — the
// stable ``verdict`` field already gives the bucket most consumers want, and
// the per-service ``security`` vocab tends to add noise to filtered exports.
const DEFAULT_SELECTED: FieldId[] = ALL_FIELDS.filter(
  (f) => f !== "unauth.security" && f !== "auth_probe.security",
);

export function ExportDialog({ open, scan, onClose }: Props) {
  const [selected, setSelected] = useState<Set<FieldId>>(
    () => new Set(DEFAULT_SELECTED),
  );

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const toggle = (id: FieldId) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const projectCount = scan?.projects.length ?? 0;
  const findingCount = useMemo(
    () => (scan?.projects ?? []).reduce((n, p) => n + p.findings.length, 0),
    [scan],
  );
  const hasRaw = Boolean(scan?.raw_document);

  const exportFull = () => {
    if (!scan) return;
    downloadScan(scan.id, `scan-${scan.id}.json`);
    onClose();
  };

  const exportSelected = () => {
    if (!scan) return;
    const filtered = buildFiltered(scan, selected);
    const blob = new Blob([JSON.stringify(filtered, null, 2)], {
      type: "application/json;charset=utf-8",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${scan.id}-filtered.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    onClose();
  };

  return (
    <div
      className={cn(
        "fixed inset-0 z-50 flex items-center justify-center p-4 transition-opacity",
        open ? "opacity-100" : "pointer-events-none opacity-0",
      )}
      aria-hidden={!open}
    >
      <div onClick={onClose} className="absolute inset-0 bg-black/50" />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Export scan"
        className={cn(
          "relative flex w-full max-w-3xl flex-col rounded-lg border border-ink-700/80 bg-ink-950 shadow-2xl transition-transform",
          open ? "scale-100" : "scale-95",
        )}
      >
        <div className="flex items-start justify-between gap-3 px-5 pb-3 pt-5">
          <div>
            <h2 className="text-base font-semibold text-ink-100">Export scan</h2>
            <p className="mt-1 text-xs text-ink-400">
              Pick fields to include in a filtered JSON, or download the full
              raw document.{" "}
              {scan && (
                <span className="font-mono text-ink-500">
                  {projectCount} project{projectCount === 1 ? "" : "s"} ·{" "}
                  {findingCount} finding{findingCount === 1 ? "" : "s"}
                </span>
              )}
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded p-1 font-mono text-sm text-ink-400 hover:bg-ink-800/60 hover:text-ink-100"
            aria-label="Close"
          >
            ✕
          </button>
        </div>

        <div className="flex items-center gap-2 px-5 pb-2 font-mono text-[10px] uppercase tracking-wider text-ink-400">
          <button
            type="button"
            onClick={() => setSelected(new Set(ALL_FIELDS))}
            className="rounded border border-ink-700/60 px-2 py-0.5 text-ink-300 hover:border-ink-500 hover:text-ink-100"
          >
            Select all
          </button>
          <button
            type="button"
            onClick={() => setSelected(new Set())}
            className="rounded border border-ink-700/60 px-2 py-0.5 text-ink-300 hover:border-ink-500 hover:text-ink-100"
          >
            Clear
          </button>
          <button
            type="button"
            onClick={() => setSelected(new Set(DEFAULT_SELECTED))}
            className="rounded border border-ink-700/60 px-2 py-0.5 text-ink-300 hover:border-ink-500 hover:text-ink-100"
          >
            Reset
          </button>
          <span className="ml-auto tabular-nums text-ink-500">
            {selected.size} / {ALL_FIELDS.length} selected
          </span>
        </div>

        <div className="grid max-h-[55vh] grid-cols-1 gap-x-6 gap-y-4 overflow-y-auto border-t border-ink-700/60 px-5 py-4 sm:grid-cols-2 lg:grid-cols-3">
          {GROUPS.map((g) => (
            <div key={g.title}>
              <div className="mb-1.5 font-mono text-[10px] uppercase tracking-wider text-ink-400">
                {g.title}
              </div>
              <ul className="space-y-1">
                {g.fields.map((f) => (
                  <li key={f.id}>
                    <label className="flex cursor-pointer items-start gap-2 font-mono text-[12px] text-ink-200 hover:text-ink-100">
                      <input
                        type="checkbox"
                        checked={selected.has(f.id)}
                        onChange={() => toggle(f.id)}
                        className="mt-0.5 h-3.5 w-3.5 rounded border-ink-600 bg-ink-900 accent-accent"
                      />
                      <span className="flex-1">
                        {f.label}
                        {f.hint && (
                          <span className="ml-1 normal-case text-[10px] text-ink-500">
                            — {f.hint}
                          </span>
                        )}
                      </span>
                    </label>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {!hasRaw && (
          <div className="border-t border-ink-700/60 px-5 py-2 font-mono text-[11px] text-severity-tenant">
            No raw document on this scan — only "Export full" is meaningful;
            filtered export will be empty.
          </div>
        )}

        <div className="flex flex-wrap items-center justify-end gap-2 border-t border-ink-700/60 bg-ink-900/40 px-4 py-3">
          <Button size="sm" variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button size="sm" variant="ghost" onClick={exportFull}>
            Export full (raw)
          </Button>
          <Button
            size="sm"
            onClick={exportSelected}
            disabled={selected.size === 0 || !hasRaw}
          >
            Export selected
          </Button>
        </div>
      </div>
    </div>
  );
}

// ---------------- builder ----------------

interface FilteredOutput {
  exported_at: string;
  fields: FieldId[];
  document: Record<string, unknown>;
}

function buildFiltered(scan: ScanDetail, sel: Set<FieldId>): FilteredOutput {
  const raw = (scan.raw_document ?? {}) as Record<string, unknown>;

  const out: Record<string, unknown> = {};

  // Scan timing
  if (sel.has("started_at")) out.started_at = raw.started_at;
  if (sel.has("finished_at")) out.finished_at = raw.finished_at;

  // Auth context
  const rawAuth = (raw.auth ?? {}) as Record<string, unknown>;
  const auth: Record<string, unknown> = {};
  if (sel.has("auth.used")) auth.used = rawAuth.used;
  if (sel.has("auth.identities")) auth.identities = rawAuth.identities;
  if (Object.keys(auth).length > 0) out.auth = auth;

  if (sel.has("extraction.bundles")) {
    const rawExtraction = (raw.extraction ?? {}) as Record<string, unknown>;
    if (Array.isArray(rawExtraction.bundles)) {
      out.extraction = { bundles: rawExtraction.bundles };
    }
  }

  // Summary
  if (sel.has("summary.per_service")) {
    const rawSummary = (raw.summary ?? {}) as Record<string, unknown>;
    out.summary = { per_service: rawSummary.per_service };
  }

  // Projects
  const projectFieldIds: FieldId[] = [
    "project.project_id",
    "project.package_names",
    "project.extracted_items",
  ];
  const findingGroupIds: FieldId[] = [
    "finding.service",
    "finding.url",
    "finding.probe",
    "finding.resource",
    "finding.error",
    "unauth.status",
    "unauth.security",
    "unauth.verdict",
    "unauth.message",
    "unauth.response_content",
    "auth_probe.status",
    "auth_probe.security",
    "auth_probe.verdict",
    "auth_probe.message",
    "auth_probe.response_content",
    "auth_probe.identity",
  ];
  const wantsAnyProject = projectFieldIds.some((k) => sel.has(k));
  const wantsAnyFinding = findingGroupIds.some((k) => sel.has(k));
  if (wantsAnyProject || wantsAnyFinding) {
    const rawProjects = Array.isArray(raw.projects)
      ? (raw.projects as Record<string, unknown>[])
      : [];
    out.projects = rawProjects.map((p) => projectShape(p, sel, wantsAnyFinding));
  }

  return {
    exported_at: new Date().toISOString(),
    fields: ALL_FIELDS.filter((f) => sel.has(f)),
    document: out,
  };
}

function projectShape(
  p: Record<string, unknown>,
  sel: Set<FieldId>,
  wantsAnyFinding: boolean,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (sel.has("project.project_id")) out.project_id = p.project_id;
  if (sel.has("project.package_names")) out.package_names = p.package_names;
  if (sel.has("project.extracted_items"))
    out.extracted_items = p.extracted_items;
  if (wantsAnyFinding) {
    const rawFindings = Array.isArray(p.findings)
      ? (p.findings as Record<string, unknown>[])
      : [];
    out.findings = rawFindings.map((f) => findingShape(f, sel));
  }
  return out;
}

function findingShape(
  f: Record<string, unknown>,
  sel: Set<FieldId>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (sel.has("finding.service")) out.service = f.service;
  if (sel.has("finding.url")) out.url = f.url;
  if (sel.has("finding.probe")) out.probe = f.probe;
  if (sel.has("finding.resource")) out.resource = f.resource;
  if (sel.has("finding.error")) out.error = f.error ?? null;

  const unauth = probeShape(
    (f.unauth ?? {}) as Record<string, unknown>,
    sel,
    "unauth",
  );
  if (unauth) out.unauth = unauth;

  if (f.auth) {
    const auth = probeShape(
      f.auth as Record<string, unknown>,
      sel,
      "auth_probe",
    );
    if (auth) out.auth = auth;
  } else if (
    sel.has("auth_probe.status") ||
    sel.has("auth_probe.security") ||
    sel.has("auth_probe.verdict") ||
    sel.has("auth_probe.message") ||
    sel.has("auth_probe.response_content") ||
    sel.has("auth_probe.identity")
  ) {
    out.auth = null;
  }
  return out;
}

function probeShape(
  p: Record<string, unknown>,
  sel: Set<FieldId>,
  prefix: "unauth" | "auth_probe",
): Record<string, unknown> | null {
  const out: Record<string, unknown> = {};
  if (sel.has(`${prefix}.status` as FieldId)) out.status = p.status;
  if (sel.has(`${prefix}.security` as FieldId)) out.security = p.security;
  if (sel.has(`${prefix}.verdict` as FieldId)) out.verdict = p.verdict;
  if (sel.has(`${prefix}.message` as FieldId)) out.message = p.message;
  if (sel.has(`${prefix}.response_content` as FieldId)) {
    // Prefer the full body when the document carries both.
    out.response_content =
      (p.response_content_full as string | undefined) ?? p.response_content;
  }
  if (prefix === "auth_probe" && sel.has("auth_probe.identity")) {
    out.identity = p.identity;
  }
  return Object.keys(out).length === 0 ? null : out;
}
