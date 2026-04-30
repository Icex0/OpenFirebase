import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";

import { Button } from "@/components/ui/Button";
import { Select } from "@/components/ui/Select";
import { StatusPill } from "@/components/ui/StatusPill";
import { Surface, SurfaceBody, SurfaceHeader } from "@/components/ui/Surface";
import { Tooltip } from "@/components/ui/Tooltip";
import { cn } from "@/lib/cn";
import type {
  ExtractionBundle,
  Finding,
  LeakedPrivateKey,
  Project,
  ServiceAccountCred,
} from "@/lib/types";

import { scanSubjects } from "./defaults";
import { ExportDialog } from "./components/ExportDialog";
import { ExtractedItems } from "./components/ExtractedItems";
import { FindingsTable } from "./components/FindingsTable";
import { LiveTerminal } from "./components/LiveTerminal";
import { RescanDialog } from "./components/RescanDialog";
import { ScanSettingsButton } from "./components/ScanSettingsButton";
import { StageTimeline } from "./components/StageTimeline";
import { useCancelScan, useRescanScan, useScan } from "./hooks";

const SERVICE_LABEL: Record<Finding["service"], string> = {
  rtdb: "RTDB",
  firestore: "Firestore",
  storage: "Storage",
  remote_config: "Remote Config",
  cloud_functions: "Cloud Functions",
};

const ALL = "__all__" as const;

type ProjectTab = "findings" | "extracted";

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { data, isLoading, error } = useScan(id);
  const cancel = useCancelScan();
  const rescan = useRescanScan();
  const [query, setQuery] = useState("");
  const [serviceFilter, setServiceFilter] = useState<string>(ALL);
  const [probeFilter, setProbeFilter] = useState<string>(ALL);
  const [unauthFilter, setUnauthFilter] = useState<string>(ALL);
  const [authFilter, setAuthFilter] = useState<string>(ALL);
  const [unauthStatusFilter, setUnauthStatusFilter] = useState<string>(ALL);
  const [authStatusFilter, setAuthStatusFilter] = useState<string>(ALL);
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const [view, setView] = useState<ProjectTab>("findings");
  const [rescanOpen, setRescanOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);

  // Reset collapse state when the underlying scan changes.
  useEffect(() => {
    setCollapsed({});
  }, [id]);

  // Group projects by their primary package, then sort within each group by
  // project_id. Mirrors the CLI's "per-package then per-project" output so
  // multi-bundle scans don't interleave projects from different APKs/IPAs.
  // Manual-mode scans have no package_names — those sort to the end by
  // project_id alone.
  const projects: Project[] = useMemo(() => {
    const xs = [...(data?.projects ?? [])];
    xs.sort((a, b) => {
      const pa = a.package_names?.[0] ?? "￿";
      const pb = b.package_names?.[0] ?? "￿";
      if (pa !== pb) return pa.localeCompare(pb);
      return a.project_id.localeCompare(b.project_id);
    });
    return xs;
  }, [data?.projects]);

  // Project-scoped credential rollup. extracted_items is unpaired strings
  // only (schema 2.0); the structured paired credentials live on
  // extraction.bundles[]. We re-attribute each bundle to the projects it
  // referenced via package_name match — same heuristic the backend already
  // uses to attach package_names to projects.
  const credsByProject = useMemo(() => {
    const map = new Map<
      string,
      {
        sas: ServiceAccountCred[];
        leaks: LeakedPrivateKey[];
        sha1: string[];
      }
    >();
    const bundles: ExtractionBundle[] =
      data?.raw_document?.extraction?.bundles ?? [];
    for (const p of projects) {
      const bag = {
        sas: [] as ServiceAccountCred[],
        leaks: [] as LeakedPrivateKey[],
        sha1: [] as string[],
      };
      const pkgs = new Set(p.package_names ?? []);
      for (const b of bundles) {
        if (!b.package_name || !pkgs.has(b.package_name)) continue;
        if (b.service_accounts) bag.sas.push(...b.service_accounts);
        if (b.leaked_private_keys) bag.leaks.push(...b.leaked_private_keys);
        for (const s of b.signatures?.sha1 ?? []) {
          if (!bag.sha1.includes(s)) bag.sha1.push(s);
        }
      }
      map.set(p.id, bag);
    }
    return map;
  }, [data?.raw_document, projects]);

  // Distinct option lists derived from the actual findings in this scan.
  const facets = useMemo(() => {
    const services = new Set<string>();
    const probes = new Set<string>();
    const unauths = new Set<string>();
    const auths = new Set<string>();
    const unauthStatuses = new Set<string>();
    const authStatuses = new Set<string>();
    for (const p of projects) {
      for (const f of p.findings) {
        services.add(f.service);
        probes.add(f.probe);
        unauths.add(f.unauth.verdict);
        if (f.auth) auths.add(f.auth.verdict);
        if (f.unauth.status) unauthStatuses.add(f.unauth.status);
        if (f.auth?.status) authStatuses.add(f.auth.status);
      }
    }
    return {
      services: Array.from(services).sort(),
      probes: Array.from(probes).sort(),
      unauths: Array.from(unauths).sort(),
      auths: Array.from(auths).sort(),
      unauthStatuses: Array.from(unauthStatuses).sort(),
      authStatuses: Array.from(authStatuses).sort(),
    };
  }, [projects]);

  const filteredProjects = useMemo(() => {
    const q = query.trim().toLowerCase();
    const passesFilters = (f: Finding) => {
      if (serviceFilter !== ALL && f.service !== serviceFilter) return false;
      if (probeFilter !== ALL && f.probe !== probeFilter) return false;
      if (unauthFilter !== ALL && f.unauth.verdict !== unauthFilter) return false;
      if (authFilter !== ALL) {
        if (authFilter === "__none__") {
          if (f.auth) return false;
        } else if (!f.auth || f.auth.verdict !== authFilter) {
          return false;
        }
      }
      if (unauthStatusFilter !== ALL && f.unauth.status !== unauthStatusFilter) return false;
      if (authStatusFilter !== ALL && (!f.auth || f.auth.status !== authStatusFilter)) return false;
      return true;
    };
    const projectLevelMatch = (p: Project) => {
      if (!q) return true;
      if (p.project_id.toLowerCase().includes(q)) return true;
      if ((p.package_names ?? []).some((n: string) => n.toLowerCase().includes(q))) return true;
      const items = p.extracted_items ?? {};
      for (const v of Object.values(items)) {
        if (!Array.isArray(v)) continue;
        for (const entry of v) {
          const s = typeof entry === "string" ? entry : JSON.stringify(entry);
          if (s.toLowerCase().includes(q)) return true;
        }
      }
      return false;
    };
    const findingMatchesSearch = (f: Finding): boolean =>
      !q || f.url.toLowerCase().includes(q);
    const findingFilterActive =
      serviceFilter !== ALL ||
      probeFilter !== ALL ||
      unauthFilter !== ALL ||
      authFilter !== ALL ||
      unauthStatusFilter !== ALL ||
      authStatusFilter !== ALL;
    return projects
      .map((p) => {
        const projectMatch = projectLevelMatch(p);
        // When the project itself matches the search, keep all its findings
        // (subject to the other filters). Otherwise require per-finding URL
        // match so users can grep for a specific endpoint across projects.
        const findings = p.findings.filter(
          (f) => passesFilters(f) && (projectMatch || findingMatchesSearch(f)),
        );
        return { project: p, findings, projectMatch };
      })
      .filter(({ findings, projectMatch }) => {
        if (q && !projectMatch && findings.length === 0) return false;
        if (findingFilterActive && findings.length === 0) return false;
        return true;
      })
      .map(({ project, findings }) => ({ ...project, findings }));
  }, [projects, query, serviceFilter, probeFilter, unauthFilter, authFilter, unauthStatusFilter, authStatusFilter]);

  const resetFilters = () => {
    setQuery("");
    setServiceFilter(ALL);
    setProbeFilter(ALL);
    setUnauthFilter(ALL);
    setAuthFilter(ALL);
    setUnauthStatusFilter(ALL);
    setAuthStatusFilter(ALL);
  };

  if (isLoading) return <p className="text-sm text-ink-400">Loading…</p>;
  if (error || !data)
    return <p className="text-sm text-severity-public">Failed to load scan.</p>;

  const allFindings = filteredProjects.flatMap((p) => p.findings);
  const live = data.status === "queued" || data.status === "running";

  const allCollapsed =
    filteredProjects.length > 0 &&
    filteredProjects.every((p) => collapsed[p.id]);
  const toggleAll = () => {
    if (allCollapsed) setCollapsed({});
    else {
      const next: Record<string, boolean> = {};
      for (const p of filteredProjects) next[p.id] = true;
      setCollapsed(next);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <Link
          to="/scans"
          className="font-mono text-[11px] uppercase tracking-wider text-ink-400 hover:text-ink-200"
        >
          ← Scans
        </Link>
        <div className="mt-2 flex flex-wrap items-center justify-between gap-4">
          <div>
            <h1 className="font-mono text-base text-ink-100">
              {(() => {
                const { kind, items } = scanSubjects(data);
                if (items.length <= 1) return data.filename;
                const label = kind === "bundle" ? "bundles" : "projects";
                return (
                  <Tooltip
                    side="bottom"
                    align="start"
                    content={
                      <div className="space-y-2">
                        <div className="font-mono text-[10px] uppercase tracking-wider text-ink-400">
                          {items.length} {label}
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
                    <span className="cursor-help underline decoration-ink-600/60 decoration-dotted underline-offset-4 hover:decoration-accent/60">
                      {data.filename}
                    </span>
                  </Tooltip>
                );
              })()}
            </h1>
            <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-ink-400">
              <StatusPill status={data.status} />
              <span className="font-mono">{new Date(data.created_at).toLocaleString("en-GB")}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ScanSettingsButton options={data.options} />
            {(data.status === "queued" || data.status === "running") && (
              <Button
                variant="ghost"
                disabled={cancel.isPending}
                onClick={() => cancel.mutate(data.id)}
              >
                Stop scan
              </Button>
            )}
            {data.status === "done" && (
              <Button variant="ghost" onClick={() => setExportOpen(true)}>
                Export…
              </Button>
            )}
            {data.status !== "queued" && data.status !== "running" && (
              <Button
                variant="ghost"
                disabled={rescan.isPending}
                onClick={() => setRescanOpen(true)}
              >
                Rescan
              </Button>
            )}
          </div>
        </div>
      </div>

      <Surface>
        <SurfaceBody>
          <StageTimeline stage={data.stage} />
        </SurfaceBody>
      </Surface>

      {data.status === "failed" && data.error_message && (
        <Surface className="border-severity-public/40">
          <SurfaceBody>
            <p className="font-mono text-xs text-severity-public">{data.error_message}</p>
          </SurfaceBody>
        </Surface>
      )}

      <LiveTerminal scanId={data.id} live={live} />

      {data.projects.length === 0 && data.status === "done" && (
        <Surface>
          <SurfaceBody>
            <p className="text-sm text-ink-400">
              No Firebase project IDs were extracted from this bundle.
            </p>
          </SurfaceBody>
        </Surface>
      )}

      {data.projects.length > 0 && (
        <Surface>
          <SurfaceBody className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="flex min-w-[260px] flex-1 items-center gap-2 rounded-md border border-ink-700 bg-ink-950/60 px-3 py-1.5 focus-within:border-ink-500">
                <input
                  type="search"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search project ID, package, API key, App ID, URL…"
                  className="flex-1 bg-transparent font-mono text-xs text-ink-100 placeholder:text-ink-500 focus:outline-none"
                />
                {query.trim() && (
                  <span className="shrink-0 font-mono text-[10px] uppercase tracking-wider tabular-nums text-ink-400">
                    {filteredProjects.length} / {projects.length}
                  </span>
                )}
              </div>
              <ViewToggle value={view} onChange={setView} />
              <Button size="sm" variant="ghost" onClick={resetFilters}>
                Reset
              </Button>
              <Button size="sm" variant="ghost" onClick={toggleAll}>
                {allCollapsed ? "Expand all" : "Collapse all"}
              </Button>
            </div>
            <div className="grid grid-cols-2 gap-2 md:grid-cols-3 lg:grid-cols-6">
              <FilterSelect
                label="Service"
                value={serviceFilter}
                onChange={setServiceFilter}
                options={facets.services.map((v) => ({
                  value: v,
                  label: SERVICE_LABEL[v as Finding["service"]] ?? v,
                }))}
              />
              <FilterSelect
                label="Probe"
                value={probeFilter}
                onChange={setProbeFilter}
                options={facets.probes.map((v) => ({ value: v, label: v }))}
              />
              <FilterSelect
                label="Unauth verdict"
                value={unauthFilter}
                onChange={setUnauthFilter}
                options={facets.unauths.map((v) => ({ value: v, label: v }))}
              />
              <FilterSelect
                label="Auth verdict"
                value={authFilter}
                onChange={setAuthFilter}
                options={[
                  { value: "__none__", label: "(no auth probe)" },
                  ...facets.auths.map((v) => ({ value: v, label: v })),
                ]}
              />
              <FilterSelect
                label="Unauth status"
                value={unauthStatusFilter}
                onChange={setUnauthStatusFilter}
                options={facets.unauthStatuses.map((v: string) => ({ value: v, label: v }))}
              />
              <FilterSelect
                label="Auth status"
                value={authStatusFilter}
                onChange={setAuthStatusFilter}
                options={facets.authStatuses.map((v: string) => ({ value: v, label: v }))}
              />
            </div>
          </SurfaceBody>
        </Surface>
      )}

      {data.projects.length > 0 && filteredProjects.length === 0 && (
        <Surface>
          <SurfaceBody>
            <p className="font-mono text-xs text-ink-400">
              No projects match the current filter.
            </p>
          </SurfaceBody>
        </Surface>
      )}

      {filteredProjects.length > 0 && (
        <p className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
          {allFindings.length} result{allFindings.length === 1 ? "" : "s"}
          {" · "}
          {filteredProjects.length} project
          {filteredProjects.length === 1 ? "" : "s"}
        </p>
      )}

      {filteredProjects.map((p) => {
        const creds = credsByProject.get(p.id) ?? {
          sas: [],
          leaks: [],
          sha1: [],
        };
        return (
          <ProjectCard
            key={p.id}
            scanId={data.id}
            project={p}
            serviceAccounts={creds.sas}
            leakedKeys={creds.leaks}
            sha1Signatures={creds.sha1}
            collapsed={!!collapsed[p.id]}
            onToggle={() =>
              setCollapsed((c) => ({ ...c, [p.id]: !c[p.id] }))
            }
            live={live}
            view={view}
          />
        );
      })}

      <ExportDialog
        open={exportOpen}
        scan={data}
        onClose={() => setExportOpen(false)}
      />

      <RescanDialog
        open={rescanOpen}
        filename={data.filename}
        loading={rescan.isPending}
        onCancel={() => setRescanOpen(false)}
        onSame={() =>
          rescan.mutate(
            { id: data.id },
            {
              onSuccess: (next) => {
                setRescanOpen(false);
                navigate(`/scans/${next.id}`);
              },
            },
          )
        }
        onChange={() => {
          const mode = data.options?.mode === "manual" ? "manual" : "bundle";
          const path = mode === "manual" ? "/scans/new/manual" : "/scans/new/bundle";
          setRescanOpen(false);
          navigate(path, {
            state: {
              rescanFromId: data.id,
              rescanFilename: data.filename,
              rescanBundleFilenames: data.bundle_filenames ?? [],
              rescanOptions: data.options ?? {},
            },
          });
        }}
      />
    </div>
  );
}

function ProjectCard({
  scanId,
  project: p,
  serviceAccounts,
  leakedKeys,
  sha1Signatures,
  collapsed,
  onToggle,
  live,
  view,
}: {
  scanId: string;
  project: Project;
  serviceAccounts: ServiceAccountCred[];
  leakedKeys: LeakedPrivateKey[];
  sha1Signatures: string[];
  collapsed: boolean;
  onToggle: () => void;
  live: boolean;
  view: ProjectTab;
}) {
  const extractedCount =
    (p.extracted_items
      ? Object.values(p.extracted_items).reduce(
          (n, v) => n + (Array.isArray(v) ? (v as unknown[]).length : 0),
          0,
        )
      : 0) +
    serviceAccounts.length +
    leakedKeys.length +
    sha1Signatures.length +
    (p.package_names?.length ?? 0);
  // Per-card tab state. Seeded by the global ``view`` and re-synced
  // whenever the global toggle changes — so the toolbar acts as a
  // "set all" while users can still flip individual cards locally.
  const [tab, setTab] = useState<ProjectTab>(view);
  useEffect(() => {
    setTab(view);
  }, [view]);

  return (
    <Surface>
      <SurfaceHeader
        onClick={onToggle}
        className="cursor-pointer hover:bg-ink-800/30"
      >
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] text-ink-500">
            {collapsed ? "▸" : "▾"}
          </span>
          <div>
            <div className="font-mono text-sm text-ink-100">{p.project_id}</div>
            {p.package_names && p.package_names.length > 0 && (
              <div className="mt-0.5 font-mono text-[11px] text-ink-400">
                {p.package_names.join(", ")}
              </div>
            )}
          </div>
        </div>
        <span className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
          {p.findings.length} result{p.findings.length === 1 ? "" : "s"}
          <span className="mx-1.5 text-ink-600">·</span>
          {extractedCount} extracted
        </span>
      </SurfaceHeader>
      {!collapsed && (
        <>
          <div
            role="tablist"
            className="flex items-center gap-1 border-b border-ink-700/60 px-4 pt-2"
            onClick={(e) => e.stopPropagation()}
          >
            <TabButton
              active={tab === "findings"}
              onClick={() => setTab("findings")}
            >
              Results
              <span className="ml-1.5 text-ink-500">{p.findings.length}</span>
            </TabButton>
            <TabButton
              active={tab === "extracted"}
              onClick={() => setTab("extracted")}
            >
              Extracted items
              <span className="ml-1.5 text-ink-500">{extractedCount}</span>
            </TabButton>
          </div>
          <SurfaceBody className="space-y-4">
            {tab === "findings" ? (
              <>
                {p.findings.length > 0 && (
                  <FindingsTable scanId={scanId} findings={p.findings} />
                )}
                {p.findings.length === 0 && live && (
                  <p className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
                    Scanning… results will appear as they're produced.
                  </p>
                )}
                {p.findings.length === 0 && !live && (
                  <p className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
                    No results.
                  </p>
                )}
              </>
            ) : extractedCount > 0 ? (
              <ExtractedItems
                items={p.extracted_items}
                serviceAccounts={serviceAccounts}
                leakedKeys={leakedKeys}
                packageNames={p.package_names ?? []}
                sha1Signatures={sha1Signatures}
              />
            ) : (
              <p className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
                Nothing was extracted for this project.
              </p>
            )}
          </SurfaceBody>
        </>
      )}
    </Surface>
  );
}

function TabButton({
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
      type="button"
      role="tab"
      aria-selected={active}
      onClick={onClick}
      className={cn(
        "-mb-px border-b-2 px-3 py-2 font-mono text-[11px] uppercase tracking-wider transition-colors",
        active
          ? "border-accent text-ink-100"
          : "border-transparent text-ink-400 hover:text-ink-200",
      )}
    >
      {children}
    </button>
  );
}

function ViewToggle({
  value,
  onChange,
}: {
  value: ProjectTab;
  onChange: (v: ProjectTab) => void;
}) {
  const opts: { value: ProjectTab; label: string }[] = [
    { value: "findings", label: "Results" },
    { value: "extracted", label: "Extracted" },
  ];
  return (
    <div
      role="tablist"
      aria-label="Project view"
      className="inline-flex items-center rounded-md border border-ink-700 bg-ink-950/60 p-0.5"
    >
      {opts.map((o) => {
        const active = o.value === value;
        return (
          <button
            key={o.value}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(o.value)}
            className={cn(
              "rounded-[5px] px-2.5 py-1 font-mono text-[11px] uppercase tracking-wider transition-colors",
              active
                ? "bg-ink-800 text-ink-100 shadow-inset-border"
                : "text-ink-400 hover:text-ink-200",
            )}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  const active = value !== ALL;
  return (
    <label className="flex flex-col gap-1">
      <span className="font-mono text-[10px] uppercase tracking-wider text-ink-500">
        {label}
      </span>
      <Select
        value={value}
        onValueChange={onChange}
        active={active}
        options={[{ value: ALL, label: "All" }, ...options]}
      />
    </label>
  );
}

