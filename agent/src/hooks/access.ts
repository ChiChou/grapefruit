import { hook } from "./core.js"

const set = new Set<InvocationListener>()

export function enable() {
  set.add(hook('libSystem.B.dylib', 'open', { args: ['char *', 'int'] }))
}

export function disable() {
  for (const h of set) h.detach()
}
