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

export async function dump(handle: string) {
  const jsc = await get(handle)  
  const topKeys = jsc.evaluateScript_('Object.keys(this)').toArray()
  const result: { [key: string]: any } = {}
  for (const key of Arr.values(topKeys)) {
    const val = jsc.objectForKeyedSubscript_(key)
    if (!val.isObject()) continue
    result[key] = description(val.toObject())
  }
  console.log(JSON.stringify(result, null, 4))
  return result
}
