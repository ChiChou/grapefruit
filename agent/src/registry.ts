type API = { [key: string]: Function };
const map = new Map<string, API>();

export function invoke(name: string, ...args: any[]) {
  const [ns, fn] = name.split('/');
  const iface = map.get(ns);
  if (!iface) throw new Error(`${ns} not found`);
  const method = iface[fn];
  if (!method) throw new Error(`${ns}/${fn} not found`);
  console.log(name, args);
  return method(...args);
}

export function expose(ns: string, iface: API) {
  if (map.has(ns)) throw new Error(`namespace collision: ${ns}`);
  map.set(ns, iface);
}

export function interfaces() {
  function *gen() {
    for (const [ns, iface] of map) {
      for (const method of Object.keys(iface)) {
        yield `${ns}/${method}`;
      }
    }
  }

  return Array.from(gen());
}