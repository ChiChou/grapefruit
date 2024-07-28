type API = { [key: string]: Function };
const interfaces = new Map<string, API>();

export function invoke(name: string, ...args: any[]) {
  const [ns, fn] = name.split('.');
  const iface = interfaces.get(ns);
  if (!iface) throw new Error(`${ns} not found`);
  const method = iface.get(fn);
  if (!method) throw new Error(`${ns}.${fn} not found`);
  return method(...args);
}

export function defineInterface(ns: string, iface: API) {
  if (interfaces.has(ns)) throw new Error(`namespace collision: ${ns}`);
  interfaces.set(ns, iface);
}
