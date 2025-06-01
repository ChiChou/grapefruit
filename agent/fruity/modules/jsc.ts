import ObjC from 'frida-objc-bridge'

import { get as getInstance } from '../lib/choose.js'
import { description } from '../bridge/dictionary.js'
import { NSObject, StringLike, NSArray, NSDictionary, NSString } from '../typings.js'

import { NS } from '../bridge/iterators.js'

interface JSContext extends NSObject {
  evaluateScript_(script: StringLike): NSObject;
  objectForKeyedSubscript_(key: StringLike): NSObject;
}

export function list() {
  const result = new Map<string, string>()
  for (const instance of ObjC.chooseSync(ObjC.classes.JSContext)) {
    result.set(instance.handle.toString(), instance.toString())
  }
  return { ...result }
}

function get(handle: string) {
  return getInstance(ObjC.classes.JSContext as JSContext, handle) as Promise<JSContext>
}

function serialize(obj: NSObject) {
  if (!obj) return obj
  if (obj.isKindOfClass_(ObjC.classes.__NSCFBoolean)) return obj.boolValue()
  if (obj.isKindOfClass_(ObjC.classes.NSNumber)) return parseFloat(obj.toString())
  if (obj.isKindOfClass_(ObjC.classes.NSString)) return obj.toString()
  if (obj.isKindOfClass_(ObjC.classes.NSArray))
    return {
      type: 'array',
      size: obj.count()
    }

  if (obj.isKindOfClass_(ObjC.classes.NSDictionary))
    return {
      type: 'dict',
      keys: NS.Dictionary.keys(obj as NSDictionary<NSObject, NSObject>),
      size: obj.count()
    }

  if ('isa' in obj.$ivars) {
    const { methods, properties } = findJSExport(obj)
    return {
      type: 'instance',
      clazz: obj.$className,
      handle: obj.handle,
      methods,
      properties
    }
  }

  return {
    type: 'class',
    clazz: obj.$className
  }
}

function findJSExport(obj: ObjC.Object) {
  for (const prot of Object.values(obj.$protocols))
    if ('JSExport' in prot.protocols)
      return prot

  throw new Error(`${obj} does not confirm to JSExport`)
}

export async function dump(handle: string) {
  const jsc = await get(handle)
  const topKeys = jsc.evaluateScript_('Object.keys(this)').toArray() as NSArray<NSString>
  const funcClass = jsc.evaluateScript_('Function')
  const result = new Map<string, any>()
  for (const key of NS.Array.values(topKeys)) {
    const val = jsc.objectForKeyedSubscript_(key as NSString)
    if (!val.isObject()) continue
    const obj = val.toObject()
    if (val.isInstanceOf_(funcClass)) {
      const funcValue = obj.isKindOfClass_(ObjC.classes.NSBlock) ? {
        type: 'block',
        handle: obj.handle,
        invoke: obj.handle.add(Process.pointerSize * 2).readPointer()
      } : {
        type: 'function',
        source: val.toString()
      }

      result.set(`${key}`, funcValue)

      if (val.toString().includes('[native code]')) {
        console.log(obj.$className)
      }
      continue
    }
    result.set(`${key}`, serialize(obj))
    console.log(key, description(obj))
  }
  return { ...result }
}

export async function run(handle: string, js: string) {
  const jsc = await get(handle)
  const val = jsc.evaluateScript_(js)
  if (val.isUndefined() && jsc.exception())
    return jsc.exception().toString()
  return val.toString()
}
