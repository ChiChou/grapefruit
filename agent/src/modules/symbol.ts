const demangle = new NativeFunction(
  Module.findExportByName('libc++abi.dylib', '__cxa_demangle')!,
  'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])

const BUF_LEN = 256 * 1024
const buf = Memory.alloc(BUF_LEN)

function cxaDemangle(name: string): string | null {
  const len = Memory.alloc(Process.pointerSize)
  const status = Memory.alloc(Process.pointerSize)

  len.writeUInt(BUF_LEN)
  const mangled = Memory.allocUtf8String(name)
  demangle(mangled, buf, len, status)

  const statusValue = status.readUInt()
  if (statusValue == 0) return buf.readUtf8String()
  console.error('__cxa_demangle failed, status: ' + statusValue.toString(16))
  return null
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
      let demangled
      try {
        demangled = cxaDemangle(sym.name)
      } catch (e) {

      }
      return demangled ? Object.assign(sym, { demangled }) : sym
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

export function resolve(type: 'objc' | 'module', query: string) {
  const matches = new ApiResolver(type).enumerateMatches(query)  
  return type === 'module' ? matches.map(item => {
    const [module, symbol] = item.name.split('!', 2)
    return Object.assign({}, item, { module, symbol })
  }) : matches
}

export function importedModules(name?: string) {
  const modules = new Set<string>()
  for (const imp of find(name).enumerateImports()) {
    if (imp.module)
      modules.add(imp.module)
  }
  return [...modules]
}

function loadDemangler() {
  const canidates = ['/usr/lib/swift', '/System/Library/PrivateFrameworks/Swift/']
  for (const base of canidates) {
    try {
      return Module.load(`${base}/libswiftDemangle.dylib`)
    } catch(e) {
      continue
    }
  }
}

let cachedSwiftDemangler: (name: string) => string | null
function swiftDemangle(name: string) {
  if (cachedSwiftDemangler) return cachedSwiftDemangler(name)
  const mod = loadDemangler()
  if (mod) {
    const demangle = new NativeFunction(mod.findExportByName('swift_demangle_getDemangledName')!, 'uint', ['pointer', 'pointer', 'uint'])
    cachedSwiftDemangler = (name: string) => {
      const len = demangle(Memory.allocUtf8String(name), buf, BUF_LEN) as number
      if (!len) return null
      return buf.readUtf8String(len)
    }
    return cachedSwiftDemangler(name)
  }
  return null
}

function tryDemangle(name: string): string | null {
  try {
    if (name.startsWith('_Z')) {
      return cxaDemangle(name)
    } else if (name.match(/(_T|_?\\$[Ss])[_a-zA-Z0-9$.]+/)) {
      return swiftDemangle(name)
    }
  } catch(e) {

  }
  return null
}

export function imported(module: string, name?: string) {
  const result = []
  for (const imp of find(name).enumerateImports()) {
    if (imp.module === module) {
      const { name, address, slot, type } = imp
      const demangled = tryDemangle(name)
      result.push({ name, address, slot, type, demangled })
    }
  }
  return result
}
