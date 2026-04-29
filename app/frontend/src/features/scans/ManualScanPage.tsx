import { useState, type ChangeEvent } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { ScanOptions } from "@/lib/types";

import { OptionsForm, type OptionsFormValue } from "./components/OptionsForm";
import { DEFAULT_OPTIONS, projectScopedCredWarning, scanOptionError, validateRtdbJson } from "./defaults";
import { useRescanScan, useUploadScan } from "./hooks";

interface RescanState {
  rescanFromId: string;
  rescanFilename: string;
  rescanBundleFilenames: string[];
  rescanOptions: Partial<ScanOptions>;
}

const EMPTY_FORM: OptionsFormValue = {
  options: { ...DEFAULT_OPTIONS, mode: "manual" },
  fuzzCollectionsFile: null,
  fuzzFunctionsFile: null,
  writeRtdbFile: null,
  writeStorageFile: null,
};

export function ManualScanPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const rescanState = (location.state as RescanState | null) ?? null;
  const isRescan = Boolean(rescanState?.rescanFromId);
  const upload = useUploadScan();
  const rescan = useRescanScan();
  const [form, setForm] = useState<OptionsFormValue>(() => {
    if (rescanState?.rescanOptions) {
      return {
        ...EMPTY_FORM,
        options: { ...DEFAULT_OPTIONS, ...rescanState.rescanOptions, mode: "manual" },
      };
    }
    return EMPTY_FORM;
  });
  const [projectIdFile, setProjectIdFile] = useState<File | null>(null);
  const [privateKeyFile, setPrivateKeyFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);

  const o = form.options;
  const setO = <K extends keyof typeof o>(k: K, v: (typeof o)[K]) =>
    setForm((f) => ({ ...f, options: { ...f.options, [k]: v } }));

  const hasProjectIds = !!projectIdFile || !!(o.project_ids && o.project_ids.trim());
  // When IDs come from a file the option-level checks can't see them; treat
  // file-supplied IDs as a single project for the auth/multi-id rule.
  const optionError = scanOptionError(
    projectIdFile && !o.project_ids ? { ...o, project_ids: "from_file" } : o,
  );
  const canSubmit = isRescan
    ? hasProjectIds && !rescan.isPending && !optionError
    : hasProjectIds && !upload.isPending && !optionError;

  const submit = async () => {
    if (!hasProjectIds) return;
    setError(null);
    if (form.options.write_rtdb && form.writeRtdbFile) {
      const msg = await validateRtdbJson(form.writeRtdbFile);
      if (msg) {
        setError(msg);
        return;
      }
    }
    if (isRescan) {
      try {
        const scan = await rescan.mutateAsync({
          id: rescanState!.rescanFromId,
          options: form.options,
        });
        navigate(`/scans/${scan.id}`);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : "Rescan failed");
      }
      return;
    }
    try {
      const scan = await upload.mutateAsync({
        files: [],
        options: form.options,
        fuzzCollectionsFile: form.fuzzCollectionsFile,
        fuzzFunctionsFile: form.fuzzFunctionsFile,
        writeRtdbFile: form.writeRtdbFile,
        writeStorageFile: form.writeStorageFile,
        projectIdFile,
        privateKeyFile,
      });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Upload failed");
    }
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">
          {isRescan ? "Rescan with new settings" : "Manual scan"}
        </h1>
        <p className="mt-1 text-sm text-ink-400">
          {isRescan
            ? "Identifiers and options are prefilled from the original scan. Adjust whatever you want before re-running."
            : "Provide Firebase identifiers directly — useful when you already extracted them from a web app or a bug-bounty report."}
        </p>
      </div>

      <div className="rounded-lg border border-ink-700/80 bg-ink-900/40">
        <div className="border-b border-ink-700/60 px-4 py-3">
          <div className="text-sm font-medium tracking-tight text-ink-100">
            Targets
          </div>
          <div className="mt-0.5 text-xs text-ink-400">
            At least one Firebase project ID is required. Paste below or upload a
            .txt list (one ID per line).
          </div>
        </div>
        <div className="space-y-3 p-4">
          <Field label="Project IDs (paste — one per line, or comma-separated)">
            <textarea
              value={o.project_ids ?? ""}
              onChange={(e) => setO("project_ids", e.target.value || null)}
              placeholder={"my-app-prod\nmy-app-staging"}
              disabled={!!projectIdFile}
              rows={4}
              className={cn(
                "block w-full rounded-md border border-ink-700 bg-ink-950/60 px-3 py-2 font-mono text-[12px] text-ink-100 placeholder:text-ink-500 focus:outline-none focus:border-accent",
                projectIdFile && "opacity-50",
              )}
              spellCheck={false}
            />
          </Field>
          <FilePicker
            label="…or upload a .txt list (overrides paste)"
            accept=".txt"
            file={projectIdFile}
            onChange={setProjectIdFile}
          />

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <Field label="App ID (--app-id)">
              <Input
                value={o.app_id ?? ""}
                onChange={(e) => setO("app_id", e.target.value.trim() || null)}
                placeholder="1:1234567890:android:abcd…"
              />
            </Field>
            <Field label="API key (--api-key)">
              <Input
                value={o.api_key ?? ""}
                onChange={(e) => setO("api_key", e.target.value.trim() || null)}
                placeholder="AIzaSy…"
              />
            </Field>
          </div>
          {projectScopedCredWarning(o, projectIdFile) && (
            <p className="rounded border border-severity-tenant/40 bg-severity-tenant/10 px-3 py-2 text-xs text-severity-tenant">
              {projectScopedCredWarning(o, projectIdFile)}
            </p>
          )}
        </div>
      </div>

      <div className="rounded-lg border border-ink-700/80 bg-ink-900/40">
        <div className="border-b border-ink-700/60 px-4 py-3">
          <div className="text-sm font-medium tracking-tight text-ink-100">
            API key restriction bypass
            <span className="ml-2 font-mono text-[10px] uppercase tracking-wider text-ink-500">
              optional
            </span>
          </div>
          <div className="mt-0.5 text-xs text-ink-400">
            Needed when the API key is locked to a specific Android cert,
            package, iOS bundle, or HTTP referer. Recommended to use when the response from the first scan tells you that the API key is restricted.
          </div>
        </div>
        <div className="grid grid-cols-1 gap-3 p-4 sm:grid-cols-2">
          <Field label="Android cert SHA-1 (--cert-sha1)">
            <Input
              value={o.cert_sha1 ?? ""}
              onChange={(e) => setO("cert_sha1", e.target.value.trim() || null)}
              placeholder="AA:BB:CC:…"
            />
          </Field>
          <Field label="Android package (--package-name)">
            <Input
              value={o.package_name ?? ""}
              onChange={(e) =>
                setO("package_name", e.target.value.trim() || null)
              }
              placeholder="com.example.app"
            />
          </Field>
          <Field label="iOS bundle ID (--ios-bundle-id)">
            <Input
              value={o.ios_bundle_id ?? ""}
              onChange={(e) =>
                setO("ios_bundle_id", e.target.value.trim() || null)
              }
              placeholder="com.example.app"
            />
          </Field>
          <Field label="Referer (--referer)">
            <Input
              value={o.referer ?? ""}
              onChange={(e) => setO("referer", e.target.value.trim() || null)}
              placeholder="https://app.example.com/"
            />
          </Field>
        </div>
      </div>

      <OptionsForm
        value={form}
        onChange={setForm}
        disabled={upload.isPending || rescan.isPending}
        showServiceAccount
        privateKeyFile={privateKeyFile}
        onPrivateKeyFileChange={setPrivateKeyFile}
      />

      {optionError && !error && (
        <p className="rounded border border-severity-public/40 bg-severity-public/10 px-3 py-2 text-xs text-severity-public">
          {optionError}
        </p>
      )}
      {error && <p className="text-sm text-severity-public">{error}</p>}

      <div className="flex items-center justify-end gap-3">
        {(upload.isPending || rescan.isPending) && (
          <span className="text-sm text-ink-400">Submitting…</span>
        )}
        <Button onClick={submit} disabled={!canSubmit}>
          {isRescan ? "Rescan" : "Start scan"}
        </Button>
      </div>
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="mb-1 block font-mono text-[11px] uppercase tracking-wider text-ink-400">
        {label}
      </span>
      {children}
    </label>
  );
}

function FilePicker({
  label,
  file,
  onChange,
  accept,
}: {
  label: string;
  file: File | null;
  onChange: (f: File | null) => void;
  accept?: string;
}) {
  const handle = (e: ChangeEvent<HTMLInputElement>) => {
    onChange(e.target.files?.[0] ?? null);
  };
  return (
    <Field label={label}>
      <div className="flex items-center gap-2">
        <input
          type="file"
          accept={accept}
          onChange={handle}
          className="block w-full text-xs text-ink-300 file:mr-3 file:rounded-md file:border file:border-ink-700 file:bg-ink-900 file:px-2.5 file:py-1.5 file:font-mono file:text-[11px] file:uppercase file:tracking-wider file:text-ink-200 hover:file:border-ink-600"
        />
        {file && (
          <button
            type="button"
            onClick={() => onChange(null)}
            className="font-mono text-[11px] uppercase tracking-wider text-ink-400 hover:text-ink-200"
          >
            clear
          </button>
        )}
      </div>
    </Field>
  );
}
