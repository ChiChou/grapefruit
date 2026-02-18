import ObjC from "frida-objc-bridge";

import { BaseMessage, bt } from "@/common/hooks/context.js";

const hooked = new Map<string, Map<string, InvocationListener>>();

interface NSMethodSignature {
  numberOfArguments(): number;
  frameLength(): number;
  // const char *, frida automatically bridges it to string
  getArgumentTypeAtIndex_(index: number): string;
  methodReturnType(): string;
}

export function swizzle(klassName: string, sel: string) {
  if (!ObjC.available) throw new Error("Objective-C runtime is not available");

  {
    const methods = hooked.get(klassName);
    if (!methods) {
      hooked.set(klassName, new Map());
    } else if (methods.has(sel)) {
      return;
    }
  }

  const klass = ObjC.classes[klassName];
  const method = klass[sel] as ObjC.ObjectMethod | undefined;

  const sig = klass.instanceMethodSignatureForSelector_(
    ObjC.selector(sel),
  ) as NSMethodSignature | null;
  if (!method || !sig) throw new Error(`Method ${klassName} ${sel} not found`);

  const argCount = sig.numberOfArguments();
  const argIsObj: boolean[] = [];
  for (let i = 2; i < argCount; i++) {
    argIsObj.push(sig.getArgumentTypeAtIndex_(i)[0] === "@");
  }
  const retIsObj = sig.methodReturnType()[0] === "@";

  const format = (isObj: boolean, v: NativePointer) =>
    isObj ? new ObjC.Object(v).toString() : `${v}`;

  const listener = Interceptor.attach(method.implementation, {
    onEnter(args) {
      const formatted = argIsObj.map((obj, i) => format(obj, args[i + 2]));
      const argsStr = formatted.length > 0 ? formatted.join(", ") : "";

      send({
        subject: "hook",
        category: "objc",
        symbol: `${klassName} ${sel}`,
        dir: "enter",
        line: `[${klassName} ${sel}](${argsStr})`,
        backtrace: bt(this.context),
        extra: { cls: klassName, sel, args: formatted },
      } satisfies BaseMessage);
    },
    onLeave(retval) {
      const retStr = format(retIsObj, retval);
      send({
        subject: "hook",
        category: "objc",
        symbol: `${klassName} ${sel}`,
        dir: "leave",
        line: `[${klassName} ${sel}] → ${retStr}`,
        backtrace: bt(this.context),
        extra: { cls: klassName, sel, ret: retStr },
      } satisfies BaseMessage);
    },
  });

  hooked.get(klassName)!.set(sel, listener);
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
