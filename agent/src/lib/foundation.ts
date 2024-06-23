function wrap(name: string) {
  return function () {
    const func = new NativeFunction(Module.findExportByName(null, name)!, 'pointer', [])
    const result = func() as NativePointer
    return new ObjC.Object(result).toString()
  }
}

export const NSTemporaryDirectory = wrap('NSTemporaryDirectory')
export const NSHomeDirectory = wrap('NSHomeDirectory')
