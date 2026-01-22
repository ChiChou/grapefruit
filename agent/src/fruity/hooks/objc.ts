import ObjC from "frida-objc-bridge";

import { BaseMessage, bt } from "./context.js";
import { parse } from "./typecoding.js";

export interface Message extends BaseMessage {
  cls: string;
  sel: string;
  args: string[];
  ret: string;
}

const hooked = new Map<string, Map<string, InvocationListener>>();

export function swizzle(cls: string, sel: string) {
  if (!ObjC.available) throw new Error("Objective-C runtime is not available");

  {
    const methods = hooked.get(cls);
    if (!methods) {
      hooked.set(cls, new Map());
    } else if (methods.has(sel)) {
      return;
    }
  }

  const method = ObjC.classes[cls][sel] as ObjC.ObjectMethod | undefined;
  if (!method) throw new Error(`Method ${cls} ${sel} not found`);

  const { types } = method;
  const parsed = parse(types);
  const format = (t: string, v: NativePointer) =>
    t === "NSObject*" ? new ObjC.Object(v).toString() : `${v}`;

  const listener = Interceptor.attach(method.implementation, {
    onEnter(args) {
      const formatted = parsed.args.map((t, i) => format(t, args[i + 2]));

      send({
        subject: "hook",
        category: "objc",
        cls,
        sel,
        symbol: `${cls} ${sel}`,
        direction: "enter",
        backtrace: bt(this.context),
        args: formatted,
      });
    },
    onLeave(retval) {
      send({
        subject: "hook",
        category: "objc",
        cls,
        sel,
        symbol: `${cls} ${sel}`,
        direction: "leave",
        backtrace: bt(this.context),
        ret: format(parsed.ret, retval),
      });
    },
  });

  hooked.get(cls)!.set(sel, listener);
}

export function unswizzle(cls: string, sel: string) {
  const methods = hooked.get(cls);
  if (!methods) return;

  const listener = methods.get(sel);
  if (!listener) return;

  listener.detach();
  methods.delete(sel);

  if (methods.size === 0) {
    hooked.delete(cls);
  }
}
