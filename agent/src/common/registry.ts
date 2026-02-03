/* eslint-disable @typescript-eslint/no-unsafe-function-type */
/* eslint-disable @typescript-eslint/no-explicit-any */

export function createRegistry<
  T extends Record<string, Record<string, unknown>>,
>(route: T) {
  function invoke(ns: string, fn: string, args: any[]) {
    const iface = route[ns as keyof typeof route];
    if (!iface) throw new Error(`${ns} not found`);
    const method = iface[fn as keyof typeof iface] as Function;
    if (!method) throw new Error(`${ns}.${fn} not found`);
    return method(...args);
  }

  function interfaces() {
    function* gen() {
      for (const [ns, iface] of Object.entries(route)) {
        for (const method of Object.keys(iface)) {
          yield `${ns}.${method}`;
        }
      }
    }

    return Array.from(gen());
  }

  return { invoke, interfaces };
}

// Type helper for RPC route
export type RPCRoute<T> = T;

// Type helper for remote RPC
export type RemoteRPC<T extends Record<string, Record<string, unknown>>> = {
  [K in keyof T]: {
    [M in keyof T[K]]: T[K][M] extends (...args: infer A) => infer R
      ? (...args: A) => Promise<Awaited<R>>
      : never;
  };
};
