// todo: rename this module to corefoundation.ts

const CFStringGetCStringPtr = new NativeFunction(
  Module.findExportByName('CoreFoundation', 'CFStringGetCStringPtr')!, 'pointer', ['pointer', 'int']);
const CFStringGetLength = new NativeFunction(
  Module.findExportByName('CoreFoundation', 'CFStringGetLength')!, 'int', ['pointer']);

function wrap(name: string) {
  return function () {
    const func = new NativeFunction(Module.findExportByName(null, name)!, 'pointer', [])
    const result = func() as NativePointer
    return new ObjC.Object(result).toString()
  }
}

export const NSTemporaryDirectory = wrap('NSTemporaryDirectory')
export const NSHomeDirectory = wrap('NSHomeDirectory')

export function CFSTR(p: NativePointer) {
  const kCFStringEncodingUTF8 = 0x08000100
  const str = CFStringGetCStringPtr(p, kCFStringEncodingUTF8) as NativePointer
  return str.readUtf8String(CFStringGetLength(p) as number)
}
