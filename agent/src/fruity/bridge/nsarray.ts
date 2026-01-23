import ObjC from "frida-objc-bridge";
import type { NSArray, NSObject } from "../typings.js";

export function* iterateNSArray(arr: NSArray<NSObject>) {
  if (!arr.isKindOfClass_(ObjC.classes.NSArray))
    throw new Error(`Unexpected class ${arr.$className}`);

  const count = arr.count();
  for (let i = 0; i < count; i++) yield arr.objectAtIndex_(i);
}
