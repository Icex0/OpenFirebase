import { ApiError, api, API_BASE, getToken } from "@/lib/api";
import type {
  LogLine,
  ResponseBody,
  ScanDetail,
  ScanOptions,
  ScanSummary,
} from "@/lib/types";

export interface UploadProgress {
  loaded: number;
  total: number;
}

export async function listScans(): Promise<ScanSummary[]> {
  return api.get<ScanSummary[]>("/scans");
}

export async function getScan(id: string): Promise<ScanDetail> {
  return api.get<ScanDetail>(`/scans/${id}`);
}

export async function getFindingBody(
  scanId: string,
  findingId: string,
  probe: "unauth" | "auth",
): Promise<ResponseBody> {
  return api.get<ResponseBody>(
    `/scans/${scanId}/findings/${findingId}/body?probe=${probe}`,
  );
}

export interface UploadPayload {
  files: File[];
  options: ScanOptions;
  fuzzCollectionsFile?: File | null;
  fuzzFunctionsFile?: File | null;
  writeRtdbFile?: File | null;
  writeStorageFile?: File | null;
  projectIdFile?: File | null;
  privateKeyFile?: File | null;
  onProgress?: (p: UploadProgress) => void;
  signal?: AbortSignal;
}

export async function uploadScan(payload: UploadPayload): Promise<ScanSummary> {
  const form = new FormData();
  for (const f of payload.files) {
    // ``webkitRelativePath`` carries the folder structure for folder picks.
    // Backend strips path components, so just pass the leaf name.
    form.append("files", f, f.name);
  }
  form.append("options", JSON.stringify(payload.options));
  if (payload.fuzzCollectionsFile)
    form.append("fuzz_collections_file", payload.fuzzCollectionsFile);
  if (payload.fuzzFunctionsFile)
    form.append("fuzz_functions_file", payload.fuzzFunctionsFile);
  if (payload.writeRtdbFile) form.append("write_rtdb_file", payload.writeRtdbFile);
  if (payload.writeStorageFile) form.append("write_storage_file", payload.writeStorageFile);
  if (payload.projectIdFile) form.append("project_id_file", payload.projectIdFile);
  if (payload.privateKeyFile) form.append("private_key_file", payload.privateKeyFile);

  // XHR (not fetch) so we can surface upload.onprogress for a progress bar.
  return await new Promise<ScanSummary>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `${API_BASE}/scans`);
    const token = getToken();
    if (token) xhr.setRequestHeader("Authorization", `Bearer ${token}`);

    xhr.upload.onprogress = (ev) => {
      if (ev.lengthComputable && payload.onProgress) {
        payload.onProgress({ loaded: ev.loaded, total: ev.total });
      }
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText) as ScanSummary);
        } catch {
          reject(new ApiError(xhr.status, "Invalid server response"));
        }
      } else {
        let detail = xhr.statusText;
        try {
          const payload = JSON.parse(xhr.responseText);
          if (typeof payload?.detail === "string") detail = payload.detail;
        } catch {
          /* keep statusText */
        }
        reject(new ApiError(xhr.status, detail));
      }
    };
    xhr.onerror = () => reject(new ApiError(0, "Network error"));
    xhr.onabort = () => reject(new ApiError(0, "Upload cancelled"));
    payload.signal?.addEventListener("abort", () => xhr.abort());

    xhr.send(form);
  });
}

export async function deleteScan(id: string): Promise<void> {
  return api.del<void>(`/scans/${id}`);
}

export async function rescanScan(
  id: string,
  newOptions?: ScanOptions,
): Promise<ScanSummary> {
  // ``options: null`` reuses the original scan's options; a populated value
  // overrides them. The backend wraps it in a RescanRequest envelope so
  // there's no ambiguity between "no override" and "empty options".
  return api.post<ScanSummary>(`/scans/${id}/rescan`, {
    options: newOptions ?? null,
  });
}

export async function cancelScan(id: string): Promise<void> {
  return api.post<void>(`/scans/${id}/cancel`);
}

export function downloadScanUrl(id: string): string {
  return `${API_BASE}/scans/${id}/download`;
}

export async function downloadScan(id: string, filename: string): Promise<void> {
  const token = getToken();
  const res = await fetch(downloadScanUrl(id), {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error("Download failed");
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export async function fetchLogs(
  id: string,
  afterSeq = 0,
  limit = 500,
): Promise<LogLine[]> {
  return api.get<LogLine[]>(
    `/scans/${id}/logs?after_seq=${afterSeq}&limit=${limit}`,
  );
}

export function scanStreamUrl(id: string): string | null {
  const token = getToken();
  if (!token) return null;
  return `${API_BASE}/scans/${id}/stream?token=${encodeURIComponent(token)}`;
}
