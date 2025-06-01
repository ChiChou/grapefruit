import ObjC from "frida-objc-bridge";
import type { NSString } from "../typings.js";

function wrap(name: string) {
  return function (): NSString {
    const impl = Module.findGlobalExportByName(name)
    if (!impl) throw new Error(`${name} not found`)

    const func = new NativeFunction(impl, 'pointer', [])
    const result = func() as NativePointer
    return new ObjC.Object(result) as NSString
  }
}

export const NSTemporaryDirectory = wrap('NSTemporaryDirectory')
export const NSHomeDirectory = wrap('NSHomeDirectory')

export const tmp = () => NSTemporaryDirectory().toString()
export const home = () => NSHomeDirectory().toString()
