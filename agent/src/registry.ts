import route from './router.js'

export function invoke(name: string, ...args: any[]) {
  const [ns, fn] = name.split('.');

  const iface = route[ns as keyof typeof route];
  if (!iface) throw new Error(`${ns} not found`);
  const method = iface[fn as keyof typeof iface] as Function;
  if (!method) throw new Error(`${ns}.${fn} not found`);
  return method(...args);
}

export function interfaces() {
  function *gen() {
    for (const [ns, iface] of Object.entries(route)) {
      for (const method of Object.keys(iface)) {
        yield `${ns}/${method}`;
      }
    }
  }

  return Array.from(gen());
}

// some incrediable typescript magic

export type RPCRoute = typeof route;

export type RemoteRPC = {
  [K in keyof RPCRoute]: {
    [M in keyof RPCRoute[K]]: RPCRoute[K][M] extends (...args: infer A) => infer R ? (...args: A) => Promise<R> : never;
  }
}
