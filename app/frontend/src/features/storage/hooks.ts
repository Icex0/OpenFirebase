import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { deleteStoredBlob, listStoredBundles } from "./api";

const KEY = ["storage", "bundles"] as const;

export function useStoredBundles() {
  return useQuery({ queryKey: KEY, queryFn: listStoredBundles });
}

export function useDeleteStoredBlob() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteStoredBlob,
    onSuccess: () => qc.invalidateQueries({ queryKey: KEY }),
  });
}
