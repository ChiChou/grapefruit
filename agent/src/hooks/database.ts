import { hook } from './core.js'

const set = new Set<InvocationListener>()

export function enable() {
  set.add(hook('libsqlite3.dylib', 'sqlite3_open', { args: ['char *', 'int'], ret: 'int' }))
  set.add(hook('libsqlite3.dylib', 'sqlite3_prepare_v2', { args: ['pointer', 'char *', 'int', 'pointer', 'pointer'] }))
  set.add(hook('libsqlite3.dylib', 'sqlite3_bind_int', { args: ['pointer', 'int', 'int'] }))
  set.add(hook('libsqlite3.dylib', 'sqlite3_bind_null', { args: ['pointer', 'int'] }))
  set.add(hook('libsqlite3.dylib', 'sqlite3_bind_text', { args: ['pointer', 'int', 'char *', 'int', 'pointer'] }))
}

export function disable() {
  for (const h of set) h.detach()
}
