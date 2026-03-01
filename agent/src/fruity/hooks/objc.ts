import ObjC from "frida-objc-bridge";

import { BaseMessage, bt } from "@/common/hooks/context.js";
import { api } from "@/fruity/bridge/runtime.js";

const hooked = new Map<string, Map<string, InvocationListener>>();

/**
 * Parse an ObjC method type encoding into per-argument "is object?" booleans.
 * Returns [retIsObj, selfIsObj, cmdIsObj, arg0IsObj, arg1IsObj, …].
 *
 * We only need to know if each slot is an ObjC object (`@`).  The parser
 * skips over type qualifiers (rnNoORV), digits (frame offsets/sizes), and
 * balanced brace/bracket groups (structs, unions, arrays) so that compound
 * types count as a single slot.
 */
function parseTypeIsObj(enc: string): boolean[] {
  const result: boolean[] = [];
  let i = 0;

  function skipType(): void {
    if (i >= enc.length) return;
    const ch = enc[i];

    // type qualifiers — skip and recurse
    if ("rnNoORV".includes(ch)) {
      i++;
      skipType();
      return;
    }

    if (ch === "{" || ch === "(") {
      // struct {name=...} or union (name=...)
      const close = ch === "{" ? "}" : ")";
      let depth = 1;
      i++;
      while (i < enc.length && depth > 0) {
        if (enc[i] === ch) depth++;
        else if (enc[i] === close) depth--;
        i++;
      }
    } else if (ch === "[") {
      // array [countType]
      let depth = 1;
      i++;
      while (i < enc.length && depth > 0) {
        if (enc[i] === "[") depth++;
        else if (enc[i] === "]") depth--;
        i++;
      }
    } else if (ch === "^") {
      // pointer to type — skip "^" then skip the pointee type
      i++;
      skipType();
    } else if (ch === "@") {
      i++;
      // "@?" = block, "@\"ClassName\"" = typed id — skip the trailer
      if (i < enc.length && enc[i] === "?") i++;
      else if (i < enc.length && enc[i] === '"') {
        i++;
        while (i < enc.length && enc[i] !== '"') i++;
        if (i < enc.length) i++; // closing quote
      }
    } else {
      // simple type (v, i, I, c, C, d, f, B, q, Q, s, S, l, L, :, #, *, ?, b (bitfield), etc.)
      i++;
    }
  }

  while (i < enc.length) {
    // skip frame-offset digits
    if (enc[i] >= "0" && enc[i] <= "9") {
      i++;
      continue;
    }
    // record whether this slot is an ObjC object
    result.push(enc[i] === "@");
    skipType();
  }
  return result;
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

  // sel may arrive with "+ " or "- " prefix from the frontend
  const isClassMethod = sel.startsWith("+ ");
  const selName =
    sel.startsWith("+ ") || sel.startsWith("- ") ? sel.substring(2) : sel;

  const selPtr = ObjC.selector(selName);
  const klass = ObjC.classes[klassName];
  const methodHandle = isClassMethod
    ? api.class_getClassMethod(klass.handle, selPtr)
    : api.class_getInstanceMethod(klass.handle, selPtr);
  if (methodHandle.isNull())
    throw new Error(`Method ${klassName} ${sel} not found`);

  const imp = api.method_getImplementation(methodHandle);
  const enc = api.method_getTypeEncoding(methodHandle).readUtf8String();

  // slots[0] = return type, slots[1] = self (@), slots[2] = _cmd (:), rest = args
  const slots = enc ? parseTypeIsObj(enc) : null;
  const retIsObj = slots?.[0] ?? false;
  const argIsObj = slots?.slice(3);

  const format = (isObj: boolean, v: NativePointer) =>
    isObj ? new ObjC.Object(v).toString() : `${v}`;

  const listener = Interceptor.attach(imp, {
    onEnter(args) {
      const formatted = argIsObj?.map((obj, i) => format(obj, args[i + 2]));
      const argsStr = formatted ? formatted.join(", ") : "";

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
      const retStr = argIsObj ? format(retIsObj, retval) : undefined;
      send({
        subject: "hook",
        category: "objc",
        symbol: `${klassName} ${sel}`,
        dir: "leave",
        line: `[${klassName} ${sel}]${retStr != null ? ` → ${retStr}` : ""}`,
        backtrace: bt(this.context),
        extra: { cls: klassName, sel, ret: retStr },
      } satisfies BaseMessage);
    },
  });

  hooked.get(klassName)!.set(sel, listener);
}

export function batchSwizzle(
  klassName: string,
  selectors: string[],
): { hooked: string[]; errors: Record<string, string> } {
  const hookedSels: string[] = [];
  const errors: Record<string, string> = {};
  for (const sel of selectors) {
    try {
      swizzle(klassName, sel);
      hookedSels.push(sel);
    } catch (e) {
      errors[sel] = (e as Error).message;
    }
  }
  return { hooked: hookedSels, errors };
}

export function batchUnswizzle(cls: string, selectors: string[]) {
  for (const sel of selectors) {
    unswizzle(cls, sel);
  }
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
