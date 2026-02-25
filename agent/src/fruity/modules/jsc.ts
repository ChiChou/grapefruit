import ObjC from "frida-objc-bridge";
import {
  NSObject,
  StringLike,
  NSArray,
  NSDictionary,
  NSString,
} from "@/fruity/typings.js";

import * as Dictionary from "@/fruity/bridge/object.js";
import { iterateNSArray } from "@/fruity/bridge/nsarray.js";
import { getTracker } from "@/fruity/lib/weak.js";

interface JSContext extends NSObject {
  evaluateScript_(script: StringLike): NSObject;
  objectForKeyedSubscript_(key: StringLike): NSObject;
}

export function list() {
  const t = getTracker();
  const result = new Map<string, string>();
  for (const instance of ObjC.chooseSync(ObjC.classes.JSContext)) {
    const handle = instance.handle.toString();
    t.put(handle, instance);
    result.set(handle, instance.toString());
  }
  return Object.fromEntries(result);
}

function get(handle: string): JSContext {
  return getTracker().get(handle) as JSContext;
}

type BridgedClass = {
  type: "class";
  clazz: string;
};

type BridgedInstance = {
  type: "instance";
  clazz: string;
  handle: string;
  methods: { [name: string]: string }; // name -> signature
  properties: { [name: string]: string }; // name -> signature
};

type BridgedArray = {
  type: "array";
  size: number;
};

type BridgedDict = {
  type: "dict";
  keys: string[];
  size: number;
};

type BridgedValue =
  | null
  | boolean
  | number
  | string
  | BridgedClass
  | BridgedInstance
  | BridgedArray
  | BridgedDict;

function serialize(obj: NSObject | null): BridgedValue {
  if (!obj) return null;
  if (obj.isKindOfClass_(ObjC.classes.__NSCFBoolean)) return obj.boolValue();
  if (obj.isKindOfClass_(ObjC.classes.NSNumber))
    return parseFloat(obj.toString());
  if (obj.isKindOfClass_(ObjC.classes.NSString)) return obj.toString();
  if (obj.isKindOfClass_(ObjC.classes.NSArray))
    return {
      type: "array",
      size: obj.count(),
    };

  if (obj.isKindOfClass_(ObjC.classes.NSDictionary))
    return {
      type: "dict",
      keys: [...Dictionary.keys(obj as NSDictionary<NSObject, NSObject>)].map(
        (k) => `${k}`,
      ),
      size: obj.count(),
    };

  if ("isa" in obj.$ivars) {
    const { methods, properties } = findJSExport(obj);
    return {
      type: "instance",
      clazz: obj.$className,
      handle: obj.handle.toString(),
      methods,
      properties,
    };
  }

  return {
    type: "class",
    clazz: obj.$className,
  };
}

function findJSExport(obj: ObjC.Object) {
  for (const prot of Object.values(obj.$protocols)) {
    if ("JSExport" in prot.protocols) {
      const { methods, properties } = prot;

      return {
        methods: Object.fromEntries(
          Object.entries(methods).map(([name, desc]) => [name, desc.types]),
        ),
        properties: Object.fromEntries(
          Object.entries(properties).map(([name, prop]) => [name, prop["T"]]),
        ),
      };
    }
  }

  throw new Error(`${obj} does not confirm to JSExport`);
}

export type BridgedBlock = {
  type: "block";
  handle: string;
  invoke: string;
};

export type JsFunction = {
  type: "function";
  source: string;
};

export type FunctionLikeDump = BridgedBlock | JsFunction;
export type DumpValue = BridgedValue | FunctionLikeDump;

export function dump(handle: string) {
  const jsc = get(handle);
  const topKeys = jsc
    .evaluateScript_("Object.keys(this)")
    .toArray() as NSArray<NSString>;
  const funcClass = jsc.evaluateScript_("Function");

  const result = new Map<string, DumpValue>();
  for (const key of iterateNSArray(topKeys)) {
    const val = jsc.objectForKeyedSubscript_(key as NSString);
    if (!val.isObject()) continue;
    const obj = val.toObject();
    if (val.isInstanceOf_(funcClass)) {
      if (obj.isKindOfClass_(ObjC.classes.NSBlock)) {
        const p = obj.handle.add(Process.pointerSize * 2).readPointer();
        const { moduleName, name } = DebugSymbol.fromAddress(p);
        const fallback = name ?? `0x${p.toString(16)}`;
        const invoke = moduleName ? `${moduleName}!${fallback}` : fallback;

        result.set(`${key}`, {
          type: "block",
          handle: `${obj.handle}`,
          invoke,
        });
      } else {
        result.set(`${key}`, {
          type: "function",
          source: val.toString(),
        });
      }

      if (val.toString().includes("[native code]")) {
        console.log(obj.$className);
      }

      continue;
    }
    result.set(`${key}`, serialize(obj));
    console.log(key, Dictionary.description(obj));
  }
  return Object.fromEntries(result);
}

export function run(handle: string, js: string) {
  const jsc = get(handle);
  const val = jsc.evaluateScript_(js);
  if (val.isUndefined() && jsc.exception()) return jsc.exception().toString();
  return val.toString();
}
