import ObjC from "frida-objc-bridge";

import { BaseMessage, bt } from "@/common/hooks/context.js";
import { parse } from "./typecoding.js";

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
    t === "id" ? new ObjC.Object(v).toString() : `${v}`;

  const listener = Interceptor.attach(method.implementation, {
    onEnter(args) {
      const formatted = parsed.args.map((t, i) => format(t, args[i + 2]));
      const argsStr = formatted.length > 0 ? formatted.join(", ") : "";

      send({
        subject: "hook",
        category: "objc",
        symbol: `${cls} ${sel}`,
        dir: "enter",
        line: `[${cls} ${sel}](${argsStr})`,
        backtrace: bt(this.context),
        extra: { cls, sel, args: formatted },
      } satisfies BaseMessage);
    },
    onLeave(retval) {
      const retStr = format(parsed.ret, retval);
      send({
        subject: "hook",
        category: "objc",
        symbol: `${cls} ${sel}`,
        dir: "leave",
        line: `[${cls} ${sel}] → ${retStr}`,
        backtrace: bt(this.context),
        extra: { cls, sel, ret: retStr },
      } satisfies BaseMessage);
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

/**
 * List all active ObjC hooks.
 */
export function list(): Array<{ cls: string; sel: string }> {
  const result: Array<{ cls: string; sel: string }> = [];

  for (const [cls, methods] of hooked) {
    for (const sel of methods.keys()) {
      result.push({ cls, sel });
    }
  }

  return result;
}
