import { NSString } from "../bridge/foundation.js"

function wrap(name: string) {
  return function (): NSString {
    const func = new NativeFunction(Module.findExportByName(null, name)!, 'pointer', [])
    const result = func() as NativePointer
    return new ObjC.Object(result) as NSString
  }
}

export const NSTemporaryDirectory = wrap('NSTemporaryDirectory')
export const NSHomeDirectory = wrap('NSHomeDirectory')

export const tmp = () => NSTemporaryDirectory().toString()
export const home = () => NSHomeDirectory().toString()
