export const wrap = (symbol: string, ret: string, args: string[]) => new NativeFunction(Module.findExportByName(null, symbol)!, ret, args)

export const dl = (name: string) => {
  return {
    sym: (symbol: string) => {
      return Module.findExportByName(name, symbol) as NativePointer
    }
  }
}