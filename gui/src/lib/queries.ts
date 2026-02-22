import { Platform, useSession } from "@/context/SessionContext";
import type { AsyncFruityRPC, AsyncDroidRPC, CommonRPC } from "@/lib/rpc";
import {
  useQuery,
  useMutation,
  useQueryClient,
  type UseQueryOptions,
  type UseMutationOptions,
} from "@tanstack/react-query";

function createRpcQuery<API>(
  platformKey: string,
  getApi: () => API | null | undefined,
) {
  return function <T>(
    key: string[],
    queryFn: (api: API) => Promise<T>,
    options?: Omit<UseQueryOptions<T, Error>, "queryKey" | "queryFn">,
  ) {
    const api = getApi();

    return useQuery({
      queryKey: [platformKey, ...key],
      queryFn: () => queryFn(api!),
      enabled: !!api && (options?.enabled ?? true),
      staleTime: 0,
      gcTime: 0,
      ...options,
    });
  };
}

function createRpcMutation<API>(
  getApi: () => API | null | undefined,
) {
  return function <TData, TVariables>(
    mutationFn: (api: API, variables: TVariables) => Promise<TData>,
    options?: Omit<UseMutationOptions<TData, Error, TVariables>, "mutationFn">,
  ) {
    const api = getApi();

    return useMutation({
      mutationFn: (variables: TVariables) => mutationFn(api!, variables),
      ...options,
    });
  };
}

export const useFruityQuery = createRpcQuery<AsyncFruityRPC>(
  "fruity",
  () => useSession().fruity,
);

export const useDroidQuery = createRpcQuery<AsyncDroidRPC>(
  "droid",
  () => useSession().droid,
);

export const useFruityMutation = createRpcMutation<AsyncFruityRPC>(
  () => useSession().fruity,
);

export const useDroidMutation = createRpcMutation<AsyncDroidRPC>(
  () => useSession().droid,
);

/**
 * Platform-aware RPC query hook. Automatically dispatches to fruity or droid
 * based on the current session platform.
 */
export function usePlatformQuery<T>(
  key: string[],
  queryFn: (api: CommonRPC) => Promise<T>,
  options?: Omit<UseQueryOptions<T, Error>, "queryKey" | "queryFn">,
) {
  const { platform } = useSession();
  const isDroid = platform === Platform.Droid;
  const callerEnabled = options?.enabled ?? true;

  const fruityResult = useFruityQuery<T>(
    key,
    queryFn,
    { ...options, enabled: callerEnabled && !isDroid },
  );

  const droidResult = useDroidQuery<T>(
    key,
    queryFn,
    { ...options, enabled: callerEnabled && isDroid },
  );

  return isDroid ? droidResult : fruityResult;
}

export { useQueryClient };
