import { NSArray, NSDictionary, _Nullable } from "../objc-types.js"

/* eslint no-use-before-define: 0 */
const NSPropertyListImmutable = 0

export function valueOf(value: _Nullable<ObjC.Object>): any {
  if (!value) return null

  const { NSArray, NSDictionary, NSNumber, __NSCFBoolean, NSDate } = ObjC.classes
  if (value.isKindOfClass_(__NSCFBoolean))
    return value.boolValue()
  if (value.isKindOfClass_(NSArray))
    return toJsArray(value as NSArray<ObjC.Object>)
  if (value.isKindOfClass_(NSDictionary))
    return toJsDict(value as NSDictionary<ObjC.Object, ObjC.Object>)
  if (value.isKindOfClass_(NSNumber))
    return parseFloat(value.toString()) // might lost precision
  if (value.isKindOfClass_(NSDate))
    return new Date(value.timeIntervalSince1970() * 1000)
  return value.toString()
}

type Dictionary = { [key: string]: any }

export function toJsDict(nsDict: NSDictionary<ObjC.Object, ObjC.Object>): Dictionary {
  const jsDict: Dictionary = {}
  const keys = nsDict.allKeys()
  const count = keys.count()
  for (let i = 0; i < count; i++) {
    const key = keys.objectAtIndex_(i)
    const value = nsDict.objectForKey_(key)
    jsDict[key.toString()] = valueOf(value)
  }

  return jsDict
}

export function fromBytes(address: NativePointer, size: number): Dictionary {
  const { NSData, NSPropertyListSerialization } = ObjC.classes
  const format = Memory.alloc(Process.pointerSize)
  const err = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const data = NSData.dataWithBytesNoCopy_length_freeWhenDone_(address, size, 0)
  const dict = NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(
    data,
    NSPropertyListImmutable,
    format,
    err,
  )

  const desc = err.readPointer()
  if (!desc.isNull())
    throw new Error(new ObjC.Object(desc).toString())

  return toJsDict(dict)
}

export function toJsArray(original: NSArray<ObjC.Object>, limit: number = Infinity): any[] {
  const arr = []
  const count = original.count()
  const len = Number.isNaN(limit) ? Math.min(count, limit) : count
  for (let i = 0; i < len; i++) {
    const val = original.objectAtIndex_(i)
    arr.push(valueOf(val))
  }
  return arr
}

export function description(obj: ObjC.Object) {
  if (!obj) return `${obj}`
  if (obj.isKindOfClass_(ObjC.classes.NSBlock))
    return `<Block ${obj.handle}, invoke=${obj.handle.add(Process.pointerSize * 2).readPointer()}>`
  if (obj.isKindOfClass_(ObjC.classes.NSArray)) return `[Array of ${obj.count()} elements]`
  if (obj.isKindOfClass_(ObjC.classes.NSDictionary)) return `{Dictionary of ${obj.count()} entries}`
  if (obj.$handle === obj.$class.$handle) return `<Class ${obj.$className}>`
  return `${obj}`
}
