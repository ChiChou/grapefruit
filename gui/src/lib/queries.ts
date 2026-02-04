import { useSession } from "@/context/SessionContext";
import type { AsyncFruityRPC, AsyncDroidRPC } from "@/lib/rpc";
import {
  useQuery,
  useMutation,
  useQueryClient,
  type UseQueryOptions,
  type UseMutationOptions,
} from "@tanstack/react-query";

/**
 * RPC query hook for iOS (fruity) platform.
 *
 * @example
 * useRpcQuery(['modules'], (api) => api.symbol.modules())
 */
export function useRpcQuery<T>(
  key: string[],
  queryFn: (api: AsyncFruityRPC) => Promise<T>,
  options?: Omit<UseQueryOptions<T, Error>, "queryKey" | "queryFn">,
) {
  const { fruity } = useSession();

  return useQuery({
    queryKey: ["fruity", ...key],
    queryFn: () => queryFn(fruity!),
    enabled: !!fruity && (options?.enabled ?? true),
    staleTime: 0,
    gcTime: 0,
    ...options,
  });
}

/**
 * RPC query hook for Android (droid) platform.
 *
 * @example
 * useDroidRpcQuery(['packages'], (api) => api.pkg.list())
 */
export function useDroidRpcQuery<T>(
  key: string[],
  queryFn: (api: AsyncDroidRPC) => Promise<T>,
  options?: Omit<UseQueryOptions<T, Error>, "queryKey" | "queryFn">,
) {
  const { droid } = useSession();

  return useQuery({
    queryKey: ["droid", ...key],
    queryFn: () => queryFn(droid!),
    enabled: !!droid && (options?.enabled ?? true),
    staleTime: 0,
    gcTime: 0,
    ...options,
  });
}

/**
 * RPC mutation hook for iOS (fruity) platform.
 *
 * @example
 * useRpcMutation((api, path) => api.fs.remove(path))
 */
export function useRpcMutation<TData, TVariables>(
  mutationFn: (api: AsyncFruityRPC, variables: TVariables) => Promise<TData>,
  options?: Omit<UseMutationOptions<TData, Error, TVariables>, "mutationFn">,
) {
  const { fruity } = useSession();

  return useMutation({
    mutationFn: (variables: TVariables) => mutationFn(fruity!, variables),
    ...options,
  });
}

/**
 * RPC mutation hook for Android (droid) platform.
 *
 * @example
 * useDroidRpcMutation((api, pkgName) => api.pkg.uninstall(pkgName))
 */
export function useDroidRpcMutation<TData, TVariables>(
  mutationFn: (api: AsyncDroidRPC, variables: TVariables) => Promise<TData>,
  options?: Omit<UseMutationOptions<TData, Error, TVariables>, "mutationFn">,
) {
  const { droid } = useSession();

  return useMutation({
    mutationFn: (variables: TVariables) => mutationFn(droid!, variables),
    ...options,
  });
}

/**
 * Hook to get the query client for cache invalidation
 */
export { useQueryClient };
