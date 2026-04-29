import { useEffect, useMemo, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";

import { Button } from "@/components/ui/Button";
import { ApiError } from "@/lib/api";
import type { ScanOptions } from "@/lib/types";

import { UploadDropzone } from "./components/UploadDropzone";
import { OptionsForm, type OptionsFormValue } from "./components/OptionsForm";
import { DEFAULT_OPTIONS, scanOptionError, validateRtdbJson } from "./defaults";
import { useRescanScan, useUploadScan } from "./hooks";
import type { UploadProgress } from "./api";

interface RescanState {
  rescanFromId: string;
  rescanFilename: string;
  rescanBundleFilenames: string[];
  rescanOptions: Partial<ScanOptions>;
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function formatRate(bytesPerSec: number): string {
  return `${formatBytes(bytesPerSec)}/s`;
}

function formatEta(seconds: number): string {
  if (!isFinite(seconds) || seconds <= 0) return "—";
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.ceil(seconds % 60);
  return `${m}m ${s}s`;
}

const EMPTY_FORM: OptionsFormValue = {
  options: DEFAULT_OPTIONS,
  fuzzCollectionsFile: null,
  fuzzFunctionsFile: null,
  writeRtdbFile: null,
  writeStorageFile: null,
};

export function UploadPage() {
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
        options: { ...DEFAULT_OPTIONS, ...rescanState.rescanOptions, mode: "bundle" },
      };
    }
    return EMPTY_FORM;
  });
  const [files, setFiles] = useState<File[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<UploadProgress | null>(null);
  const startRef = useRef<number | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const optionError = scanOptionError(form.options);
  const canSubmit = isRescan
    ? !rescan.isPending && !optionError
    : files.length > 0 && !upload.isPending && !optionError;
  const totalBytes = files.reduce((acc, f) => acc + f.size, 0);
  // For rescans, the original bundle list determines whether google_id_token
  // is allowed (single bundle). For fresh uploads, it's the staged file count.
  const bundleCount = isRescan
    ? rescanState!.rescanBundleFilenames.length
    : files.length;
  const allowGoogleIdToken = bundleCount <= 1;

  const pct = progress && progress.total > 0 ? (progress.loaded / progress.total) * 100 : 0;
  const elapsed = progress && startRef.current ? (Date.now() - startRef.current) / 1000 : 0;
  const rate = elapsed > 0 && progress ? progress.loaded / elapsed : 0;
  const eta = rate > 0 && progress ? (progress.total - progress.loaded) / rate : Infinity;
  // Past 99.5% the server is still parsing the multipart body and writing to
  // MinIO, so the bytes counter is maxed but the request isn't done. Surface
  // that honestly instead of sitting at 100% looking frozen.
  const finalizing = pct >= 99.5 && upload.isPending;

  // Drop any lingering Google ID token when batch mode becomes active.
  useEffect(() => {
    if (!allowGoogleIdToken && form.options.google_id_token) {
      setForm((f) => ({
        ...f,
        options: { ...f.options, google_id_token: null },
      }));
    }
  }, [allowGoogleIdToken, form.options.google_id_token]);

  const submit = async () => {
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
    if (files.length === 0) return;
    setProgress({ loaded: 0, total: totalBytes });
    startRef.current = Date.now();
    abortRef.current = new AbortController();
    try {
      const scan = await upload.mutateAsync({
        files,
        options: form.options,
        fuzzCollectionsFile: form.fuzzCollectionsFile,
        fuzzFunctionsFile: form.fuzzFunctionsFile,
        writeRtdbFile: form.writeRtdbFile,
        writeStorageFile: form.writeStorageFile,
        onProgress: setProgress,
        signal: abortRef.current.signal,
      });
      navigate(`/scans/${scan.id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Upload failed");
      setProgress(null);
      startRef.current = null;
    }
  };

  const cancelUpload = () => {
    abortRef.current?.abort();
  };

  return (
    <div className="mx-auto max-w-3xl space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">
          {isRescan ? "Rescan with new settings" : "New scan"}
        </h1>
        <p className="mt-1 text-sm text-ink-400">
          {isRescan
            ? "Original bundles and any uploaded wordlists / write payloads are reused — only scan options change."
            : "The APK/IPA is discarded after extraction. Only scan results are kept."}
        </p>
      </div>

      {isRescan ? (
        <div className="rounded-lg border border-ink-700/80 bg-ink-900/40">
          <div className="flex items-center justify-between border-b border-ink-700/60 px-4 py-2.5">
            <div className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
              {rescanState!.rescanBundleFilenames.length} bundle
              {rescanState!.rescanBundleFilenames.length === 1 ? "" : "s"} from
              original scan
            </div>
            <span className="font-mono text-[10px] uppercase tracking-wider text-ink-500">
              reused
            </span>
          </div>
          <ul className="max-h-48 overflow-y-auto px-4 py-2 text-sm">
            {rescanState!.rescanBundleFilenames.map((name, i) => (
              <li
                key={`${name}-${i}`}
                className="truncate py-0.5 font-mono text-[12px] text-ink-200"
              >
                {name}
              </li>
            ))}
            {rescanState!.rescanBundleFilenames.length === 0 && (
              <li className="py-0.5 font-mono text-[11px] text-ink-500">
                (none)
              </li>
            )}
          </ul>
        </div>
      ) : files.length > 0 ? (
        <div className="rounded-lg border border-ink-700/80 bg-ink-900/40">
          <div className="flex items-center justify-between border-b border-ink-700/60 px-4 py-2.5">
            <div className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
              {files.length} file{files.length === 1 ? "" : "s"} ·{" "}
              {(totalBytes / 1024 / 1024).toFixed(1)} MB
            </div>
            <button
              type="button"
              onClick={() => setFiles([])}
              className="font-mono text-[11px] uppercase tracking-wider text-ink-400 hover:text-ink-200"
            >
              clear
            </button>
          </div>
          <ul className="max-h-48 overflow-y-auto px-4 py-2 text-sm">
            {files.map((f, i) => (
              <li
                key={`${f.name}-${i}`}
                className="flex items-center justify-between gap-3 py-0.5 font-mono text-[12px] text-ink-200"
              >
                <span className="truncate">{f.name}</span>
                <span className="shrink-0 text-[11px] text-ink-400">
                  {(f.size / 1024 / 1024).toFixed(1)} MB
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : (
        <UploadDropzone onFiles={setFiles} disabled={upload.isPending} />
      )}

      <OptionsForm
        value={form}
        onChange={setForm}
        disabled={upload.isPending || rescan.isPending}
        allowGoogleIdToken={allowGoogleIdToken}
      />

      {optionError && !error && (
        <p className="rounded border border-severity-public/40 bg-severity-public/10 px-3 py-2 text-xs text-severity-public">
          {optionError}
        </p>
      )}
      {error && <p className="text-sm text-severity-public">{error}</p>}

      {upload.isPending && progress && (
        <div className="overflow-hidden rounded-lg border border-ink-700/80 bg-ink-900/40">
          <div className="flex items-center justify-between px-4 pt-3">
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-[11px] uppercase tracking-wider text-ink-400">
                {finalizing ? "Finalizing" : "Uploading"}
              </span>
              <span className="font-mono text-sm tabular-nums text-ink-100">
                {pct.toFixed(1)}%
              </span>
            </div>
            <div className="flex items-center gap-4 font-mono text-[11px] tabular-nums text-ink-400">
              <span>
                {formatBytes(progress.loaded)} / {formatBytes(progress.total)}
              </span>
              {!finalizing && rate > 0 && <span>{formatRate(rate)}</span>}
              {!finalizing && rate > 0 && <span>ETA {formatEta(eta)}</span>}
            </div>
          </div>
          <div className="relative mt-3 h-1.5 w-full overflow-hidden bg-ink-800/60">
            {finalizing ? (
              <div className="absolute inset-y-0 left-0 w-1/4 animate-shimmer bg-gradient-to-r from-transparent via-accent to-transparent" />
            ) : (
              <div
                className="h-full bg-accent transition-[width] duration-150 ease-out"
                style={{ width: `${pct}%` }}
              />
            )}
          </div>
        </div>
      )}

      <div className="flex items-center justify-end gap-3">
        {!isRescan && upload.isPending && (
          <button
            type="button"
            onClick={cancelUpload}
            className="font-mono text-[11px] uppercase tracking-wider text-ink-400 hover:text-ink-200"
          >
            cancel
          </button>
        )}
        {isRescan && rescan.isPending && (
          <span className="text-sm text-ink-400">Submitting…</span>
        )}
        <Button onClick={submit} disabled={!canSubmit}>
          {isRescan ? "Rescan" : "Start scan"}
        </Button>
      </div>
    </div>
  );
}
