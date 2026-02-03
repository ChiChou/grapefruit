import { useSession } from "@/context/SessionContext";
import {
  useQuery,
  useMutation,
  useQueryClient,
  type UseQueryOptions,
  type UseMutationOptions,
} from "@tanstack/react-query";
import type { AsyncFruityRPC } from "@/lib/rpc";

/**
 * Factory for RPC queries that depend on api being ready.
 */
export function useRpcQuery<T>(
  key: string[],
  queryFn: (api: AsyncFruityRPC) => Promise<T>,
  options?: Omit<UseQueryOptions<T, Error>, "queryKey" | "queryFn">
) {
  const { api } = useSession();
  return useQuery({
    queryKey: key,
    queryFn: () => queryFn(api!),
    enabled: !!api && (options?.enabled ?? true),
    ...options,
  });
}

/**
 * Factory for RPC mutations
 */
export function useRpcMutation<TData, TVariables>(
  mutationFn: (api: AsyncFruityRPC, variables: TVariables) => Promise<TData>,
  options?: Omit<UseMutationOptions<TData, Error, TVariables>, "mutationFn">
) {
  const { api } = useSession();
  return useMutation({
    mutationFn: (variables: TVariables) => mutationFn(api!, variables),
    ...options,
  });
}

/**
 * Hook to get the query client for cache invalidation
 */
export { useQueryClient };
