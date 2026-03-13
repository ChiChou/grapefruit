import ObjC from "frida-objc-bridge";
/* eslint-disable @typescript-eslint/no-explicit-any */
import type {
  _Nullable,
  NSArray,
  NSDictionary,
  NSObject,
} from "@/fruity/typings.js";
import { iterateNSArray } from "./nsarray.js";

const NSPropertyListImmutable = 0;

export function* keys(dict: NSDictionary<NSObject, NSObject>) {
  if (!dict.isKindOfClass_(ObjC.classes.NSDictionary))
    throw new Error(`Unexpected class ${dict.$className}`);
  yield* iterateNSArray(dict.allKeys());
}

export function toJS(value: _Nullable<ObjC.Object>): any {
  if (!value) return null;

  const { NSArray, NSData, NSDictionary, NSNumber, __NSCFBoolean, NSDate } =
    ObjC.classes;
  if (value.isKindOfClass_(__NSCFBoolean)) return value.boolValue();
  if (value.isKindOfClass_(NSArray))
    return toJsArray(value as NSArray<ObjC.Object>);
  if (value.isKindOfClass_(NSDictionary))
    return toJsDict(value as NSDictionary<ObjC.Object, ObjC.Object>);
  if (value.isKindOfClass_(NSNumber)) return parseFloat(value.toString()); // might lost precision
  if (value.isKindOfClass_(NSDate))
    return new Date(value.timeIntervalSince1970() * 1000);
  if (value.isKindOfClass_(NSData))
    return (value.bytes() as NativePointer).readByteArray(value.length());
  return value.toString();
}

type Dictionary = { [key: string]: any };

export function toJsDict(
  nsDict: NSDictionary<ObjC.Object, ObjC.Object>,
): Dictionary {
  const jsDict: Dictionary = {};
  const keys = nsDict.allKeys();
  const count = keys.count();
  for (let i = 0; i < count; i++) {
    const key = keys.objectAtIndex_(i);
    const value = nsDict.objectForKey_(key);
    jsDict[key.toString()] = toJS(value);
  }

  return jsDict;
}

export function fromBytes(address: NativePointer, size: number): Dictionary {
  const { NSData, NSPropertyListSerialization } = ObjC.classes;
  const format = Memory.alloc(Process.pointerSize);
  const err = Memory.alloc(Process.pointerSize).writePointer(NULL);
  const data = NSData.dataWithBytesNoCopy_length_freeWhenDone_(
    address,
    size,
    0,
  );
  const dict =
    NSPropertyListSerialization.propertyListFromData_mutabilityOption_format_errorDescription_(
      data,
      NSPropertyListImmutable,
      format,
      err,
    );

  const desc = err.readPointer();
  if (!desc.isNull()) throw new Error(new ObjC.Object(desc).toString());

  return toJsDict(dict);
}

export function toJsArray(
  original: NSArray<ObjC.Object>,
  limit: number = Infinity,
): any[] {
  const arr = [];
  const count = original.count();
  const len = Number.isNaN(limit) ? Math.min(count, limit) : count;
  for (let i = 0; i < len; i++) {
    const val = original.objectAtIndex_(i);
    arr.push(toJS(val));
  }
  return arr;
}

export function toObjC(value: unknown): ObjC.Object {
  if (value === null || value === undefined) return ObjC.classes.NSNull.null();
  if (typeof value === "string")
    return ObjC.classes.NSString.stringWithString_(value);
  if (typeof value === "number")
    return ObjC.classes.NSNumber.numberWithDouble_(value);
  if (typeof value === "boolean")
    return ObjC.classes.NSNumber.numberWithBool_(value ? 1 : 0);
  if (value instanceof Date)
    return ObjC.classes.NSDate.dateWithTimeIntervalSince1970_(
      value.getTime() / 1000,
    );
  if (Array.isArray(value)) {
    const arr = ObjC.classes.NSMutableArray.alloc().init();
    for (const item of value) arr.addObject_(toObjC(item));
    return arr;
  }
  if (typeof value === "object") {
    const dict = ObjC.classes.NSMutableDictionary.alloc().init();
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      dict.setObject_forKey_(
        toObjC(v),
        ObjC.classes.NSString.stringWithString_(k),
      );
    }
    return dict;
  }
  return ObjC.classes.NSString.stringWithString_(String(value));
}

export function description(obj: ObjC.Object) {
  if (!obj) return `${obj}`;
  if (obj.isKindOfClass_(ObjC.classes.NSBlock))
    return `<Block ${obj.handle}, invoke=${obj.handle.add(Process.pointerSize * 2).readPointer()}>`;
  if (obj.isKindOfClass_(ObjC.classes.NSArray))
    return `[Array of ${obj.count()} elements]`;
  if (obj.isKindOfClass_(ObjC.classes.NSDictionary))
    return `{Dictionary of ${obj.count()} entries}`;
  if (obj.handle.equals(obj.$class.handle)) return `<Class ${obj.$className}>`;
  return `${obj}`;
}
