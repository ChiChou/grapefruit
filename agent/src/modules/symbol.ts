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
      const demangled = DebugSymbol.fromAddress(sym.address!).name
      return Object.assign(sym, { demangled })
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

export function imp(name?: string) {
  return uniqueAndDemangle<ModuleImportDetails>(find(name).enumerateImports())
}

export function exp(name: string) {
  const mod = name || Process.enumerateModules()[0].name
  return uniqueAndDemangle<ModuleExportDetails>(find(name).enumerateExports())
}
