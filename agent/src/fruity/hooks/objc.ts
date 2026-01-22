import ObjC from "frida-objc-bridge";

import { BaseMessage, bt } from "./context.js";
import { parse } from "./typecoding.js";

export interface ObjCMessage extends BaseMessage {
  cls: string;
  sel: string;
  args: string[];
  ret: string;
}

export function swizzle(cls: string, sel: string) {
  if (!ObjC.available) throw new Error("Objective-C runtime is not available");

  const method = ObjC.classes[cls][sel] as ObjC.ObjectMethod | undefined;
  if (!method) throw new Error(`Method ${cls} ${sel} not found`);

  const { types } = method;
  const parsed = parse(types);
  const format = (t: string, v: NativePointer) =>
    t === "NSObject*" ? new ObjC.Object(v).toString() : `${v}`;

  Interceptor.attach(method.implementation, {
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
}
