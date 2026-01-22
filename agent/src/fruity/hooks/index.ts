import ObjC from "frida-objc-bridge";

import * as crypto from "./crypto.js";
import { BaseMessage, bt } from "./context.js";

const active = new Map<string, InvocationListener[]>();

export interface ObjCMessage extends BaseMessage {
  cls: string;
  sel: string;
}

export function swizzle(cls: string, sel: string) {
  if (!ObjC.available) throw new Error("Objective-C runtime is not available");

  const method = ObjC.classes[cls][sel] as ObjC.ObjectMethod | undefined;
  if (!method) throw new Error(`Method ${cls} ${sel} not found`);

  // todo: we need to port this to frida
  // https://github.com/leptos-null/ClassDumpRuntime/blob/d417a932dc8af677/ClassDump/Services/CDTypeParser.m#L189

  Interceptor.attach(method.implementation, {
    onEnter(args) {
      // todo: dump arguments based on
      // method.argumentTypes
      send({
        subject: "hook",
        category: "objc",
        cls,
        sel,
        symbol: `${cls} ${sel}`,
        direction: "enter",
        backtrace: bt(this.context),
      });
    },
    onLeave(retval) {
      // todo: get return value using
      // method.returnType
      send({
        subject: "hook",
        category: "objc",
        cls,
        sel,
        symbol: `${cls} ${sel}`,
        direction: "leave",
        backtrace: bt(this.context),
      });
    },
  });
}

function get(group: string) {
  if (group === "crypto") {
    return [
      ...crypto.cccrypt(),
      ...crypto.x509(),
      ...crypto.hmac(),
      ...crypto.hash(),
    ];
  }
}

export function start(group: string) {
  if (active.has(group)) return;
  const hooks = get(group);
  if (!hooks) return;
  active.set(group, hooks);
}

export function stop(group: string) {
  const hooks = active.get(group);
  if (!hooks) return;
  for (const hook of hooks) {
    hook.detach();
  }
  active.delete(group);
}
