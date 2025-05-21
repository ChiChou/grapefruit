import ObjC from 'frida-objc-bridge'
import { get as getInstance } from '../lib/choose.js'
import { description } from '../lib/dict.js'
import { Arr, Dict } from '../lib/iterators.js'

type JSCCollection = { [handle: string]: string }

export function list() {
  const result: JSCCollection = {}
  for (const instance of ObjC.chooseSync(ObjC.classes.JSContext)) {
    result[instance.handle.toString()] = instance.toString()
  }
  return result
}

export function get(handle: string): Promise<ObjC.Object> {
  return getInstance(ObjC.classes.JSContext, handle)
}

function serialize(obj: ObjC.Object) {
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
      keys: Dict.keys(obj),
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

  throw new Error(`${obj} does not confirms to JSExport`)
}

export async function dump(handle: string) {
  const jsc = await get(handle)
  const topKeys = jsc.evaluateScript_('Object.keys(this)').toArray()
  const funcClass = jsc.evaluateScript_('Function')
  const result: { [key: string]: any } = {}
  for (const key of Arr.values(topKeys)) {
    const val = jsc.objectForKeyedSubscript_(key)
    if (!val.isObject()) continue
    const obj = val.toObject()
    if (val.isInstanceOf_(funcClass)) {
      result[key] = obj.isKindOfClass_(ObjC.classes.NSBlock) ? {
        type: 'block',
        handle: obj.handle,
        invoke: obj.handle.add(Process.pointerSize * 2).readPointer()
      } : {
        type: 'function',
        source: val.toString()
      }

      if (val.toString().includes('[native code]')) {
        console.log(obj.$className)
      }
      continue
    }
    result[key] = serialize(obj)
    console.log(key, description(obj))
  }
  return result
}

export async function run(handle: string, js: string) {
  const jsc = await get(handle)
  const val = jsc.evaluateScript_(js)
  if (val.isUndefined() && jsc.exception())
    return jsc.exception().toString()
  return val.toString()
}
