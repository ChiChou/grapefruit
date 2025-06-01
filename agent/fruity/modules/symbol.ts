const BUF_LEN = 256 * 1024
const buf = Memory.alloc(BUF_LEN)

function cxaDemangle(name: string): string | null {
  const libcxxabi = Process.findModuleByName('libc++abi.dylib')
  if (!libcxxabi) return null

  const demangle = new NativeFunction(
    libcxxabi.findExportByName('__cxa_demangle')!,
    'pointer', ['pointer', 'pointer', 'pointer', 'pointer'])

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

export function modules() {
  return Process.enumerateModules()
}

function find(name?: string): Module {
  if (name)
    return Process.findModuleByName(name)!
  const [main, ] = Process.enumerateModules()
  return main
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
    } catch (e) {
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
    } else if (name.match(/(_T|_?\$[Ss])[_a-zA-Z0-9$.]+/)) {
      return swiftDemangle(name)
    }
  } catch (e) {

  }
  return null
}

export function imported(name: string, module: string) {
  const unique = new Set<number>()
  return find(name).enumerateImports()
    .filter(imp => imp.module === module)
    .filter(imp => {
      if (!imp.address) return false
      const key = imp.address.toInt32()
      if (unique.has(key)) return false
      unique.add(key)
      return true
    })
    .map(imp => {
      const { name, address, slot, type } = imp
      const demangled = tryDemangle(name)
      return { name, address, slot, type, demangled }
    })
}

export function symbols(name?: string, keyword?: string) {
  let canidates = find(name).enumerateSymbols()
    .filter(sym => sym.name !== '<redacted>' && !sym.address.isNull())

  if (typeof keyword === 'string' && keyword.length)
    canidates = canidates.filter(sym => sym.name.toLowerCase().includes(keyword.toLowerCase()))

  return {
    count: canidates.length,
    list: canidates.slice(0, 200)
      .map(sym => {
        const { name, address } = sym
        const demangled = tryDemangle(name)
        let type = undefined
        if (sym.name !== '_mh_execute_header' && sym.section?.id.endsWith('__TEXT.__text'))
          type = 'function'

        if (sym.name.startsWith('OBJC_CLASS_$_'))
          type = 'variable'

        return {
          global: sym.isGlobal,
          type,
          name,
          demangled,
          address
        }
      })
    }
}

export function exported(name?: string, keyword?: string) {
  let canidates = find(name).enumerateExports()
  if (typeof keyword === 'string' && keyword.length)
    canidates = canidates.filter(exp => exp.name.toLowerCase().includes(keyword.toLowerCase()))

  return {
    count: canidates.length,
    list: canidates.slice(0, 200).map(exp => {
      const { name, address, type } = exp
      const demangled = tryDemangle(exp.name)
      return { name, address, type, demangled }
    })
  }
}

