const demangle = new NativeFunction(
  Module.findExportByName('libc++abi.dylib', '__cxa_demangle')!,
  'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])
 
const BUF_LEN = 256 * 1024
const buf = Memory.alloc(BUF_LEN)

function cxaDemangle(name: string) {
  const len = Memory.alloc(Process.pointerSize)
  const status = Memory.alloc(Process.pointerSize)

  len.writeUInt(BUF_LEN)
  const mangled = Memory.allocUtf8String(name)
  demangle(mangled, buf, len, status)

  const statusValue = status.readUInt()
  if (statusValue == 0) return buf.readUtf8String()

  throw new Error('__cxa_demangle failed, status: ' + statusValue)
}

function uniqueAndDemangle<T>(list: T[]) {
  const set = new Set()
  return list.filter((symbol) => {
    const key = (symbol as unknown as ModuleImportDetails).address
    if (set.has(key))
      return false
    set.add(key)
    return true
  }).map((symbol) => {
    const sym = (symbol as unknown as ModuleImportDetails)
    if (sym.name.startsWith('_Z')) {
      try {
        const demangled = cxaDemangle(sym.name)
        return Object.assign(sym, { demangled })
      } finally {

      }
    }
    return sym
  })
}

export function modules() {
  return Process.enumerateModules()
}

function find(name?: string): Module {
  if (name)
    return Process.findModuleByName(name)!
  const [main, ] = Process.enumerateModules()
  return main
}

export function imps(name?: string) {
  return uniqueAndDemangle<ModuleImportDetails>(find(name).enumerateImports())
}

export function exps(name: string) {
  const mod = name || Process.enumerateModules()[0].name
  return uniqueAndDemangle<ModuleExportDetails>(find(name).enumerateExports())
}
