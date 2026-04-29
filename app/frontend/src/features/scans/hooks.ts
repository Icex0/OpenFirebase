import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import type { ScanDetail, ScanOptions } from "@/lib/types";

import {
  cancelScan,
  deleteScan,
  getFindingBody,
  getScan,
  listScans,
  rescanScan,
  uploadScan,
} from "./api";

const SCANS_KEY = ["scans"] as const;

export function useScans() {
  return useQuery({
    queryKey: SCANS_KEY,
    queryFn: listScans,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      return data.some((s) => s.status === "queued" || s.status === "running") ? 3000 : false;
    },
  });
}

export function useScan(id: string | undefined) {
  return useQuery({
    queryKey: ["scan", id],
    queryFn: () => getScan(id!),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const data = query.state.data as ScanDetail | undefined;
      if (!data) return false;
      // Poll during running so extracted projects appear without waiting on a
      // manual refresh. SSE covers logs; this covers structured-data updates.
      return data.status === "queued" || data.status === "running" ? 2000 : false;
    },
  });
}

export function useUploadScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: uploadScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCANS_KEY }),
  });
}

export function useDeleteScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteScan,
    onSuccess: () => qc.invalidateQueries({ queryKey: SCANS_KEY }),
  });
}

export function useRescanScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, options }: { id: string; options?: ScanOptions }) =>
      rescanScan(id, options),
    onSuccess: () => qc.invalidateQueries({ queryKey: SCANS_KEY }),
  });
}

export function useFindingBody(
  scanId: string | undefined,
  findingId: string | undefined,
  probe: "unauth" | "auth",
  enabled: boolean,
) {
  return useQuery({
    queryKey: ["finding-body", scanId, findingId, probe],
    queryFn: () => getFindingBody(scanId!, findingId!, probe),
    enabled: enabled && Boolean(scanId) && Boolean(findingId),
    // Bodies are immutable for a given finding — cache aggressively.
    staleTime: Infinity,
    gcTime: 5 * 60 * 1000,
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: cancelScan,
    onSuccess: (_data, id) => {
      qc.invalidateQueries({ queryKey: SCANS_KEY });
      qc.invalidateQueries({ queryKey: ["scan", id] });
    },
  });
}
