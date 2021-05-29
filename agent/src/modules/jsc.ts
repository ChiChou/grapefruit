import { get as getInstance } from '../lib/choose'
import { description } from '../lib/dict'
import { Arr, Dict } from '../lib/iterators'

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
  if (obj.isKindOfClass_(ObjC.classes.NSBlock))
    return {
      type: 'block',
      handle: obj.handle,
      invoke: obj.handle.add(Process.pointerSize * 2).readPointer()
    }

  if (obj.isKindOfClass_(ObjC.classes.NSArray))
    return {
      type: 'array',
      size: obj.count()
    }

  if (obj.isKindOfClass_(ObjC.classes.NSDictionary))
    return {
      type: 'dict',
      size: obj.count()
    }

  if ('isa' in obj.$ivars) 
    return {
      type: 'instance',
      clazz: obj.$className,
      handle: obj.handle
    }
  
  return {
    type: 'class',
    name: obj.$className
  }
}

export async function dump(handle: string) {
  const jsc = await get(handle)
  const topKeys = jsc.evaluateScript_('Object.keys(this)').toArray()
  const result: { [key: string]: any } = {}
  for (const key of Arr.values(topKeys)) {
    const val = jsc.objectForKeyedSubscript_(key)
    if (!val.isObject()) continue
    const obj = val.toObject()
    result[key] = serialize(obj)
    console.log(key, description(obj))
  }
  return result
}

export async function run(handle: string, js: string) {
  const jsc = await get(handle)
  const val = jsc.evaluateScript_(js)
  if (val.isUndefined())
    return jsc.exception()?.toString()
  return val.toString()
}
