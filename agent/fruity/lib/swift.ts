const size = 1024

let buf: NativePointer
let demangler: (symbol: string) => string

export function demangle(symbol: string) {
  if (demangler) return demangler(symbol)

  const load = () => {
    const canidates = [
      '/System/Library/PrivateFrameworks/Swift/libswiftDemangle.dylib',
      '/usr/lib/swift/libswiftDemangle.dylib'
    ]

    for (const path of canidates) {
      try {
        Module.load(path)
        return true
      } catch(e) {
        continue
      }
    }

    return false
  }

  if (load()) {
    const p = Module.findExportByName('libswiftDemangle.dylib', 'swift_demangle_getDemangledName')
    if (p) {
      const getDemangledName = new NativeFunction(p, 'uint', ['pointer', 'pointer', 'uint'])
      buf = Memory.alloc(size)
      demangler = (symbol: string) => {
        const len = getDemangledName(Memory.allocUtf8String(symbol), buf, size) as number
        if (!len) {
          console.log('failed to demangle name', symbol)
          return symbol
        }
        return buf.readUtf8String(len)!
      }
      return demangler(symbol)
    }
  }

  console.warn('Unable to find swift demangler')
  return symbol
}
