import { api } from "@/lib/api";

export interface StoredScanRef {
  scan_id: string;
  scan_filename: string;
  created_at: string;
}

export interface StoredBlob {
  sha256: string;
  size: number;
  filenames: string[];
  scans: StoredScanRef[];
}

export async function listStoredBundles(): Promise<StoredBlob[]> {
  return api.get<StoredBlob[]>("/storage/bundles");
}

export async function deleteStoredBlob(sha256: string): Promise<void> {
  return api.del<void>(`/storage/bundles/${sha256}`);
}
