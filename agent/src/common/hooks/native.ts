import ObjC from "frida-objc-bridge";

import { getGlobalExport } from "@/lib/polyfill.js";
import { BaseMessage, bt } from "./context.js";

export interface NativeHookSignature {
  args: string[];
  returns: string;
}

const hooked = new Map<string | null, Map<string, InvocationListener>>();
const signatures = new Map<string | null, Map<string, NativeHookSignature>>();

function formatArg(arg: NativePointer, type: string): string {
  switch (type) {
    case "int":
      return arg.toInt32().toString();
    case "uint":
      return arg.toUInt32().toString();
    case "long":
      return int64(arg.toString()).toString();
    case "float":
    case "double":
      return arg.toInt32().toString();
    case "bool":
      return arg.toInt32() !== 0 ? "true" : "false";
    case "char *": {
      if (arg.isNull()) return "NULL";
      return JSON.stringify(arg.readUtf8String());
    }
    case "void *":
      return arg.toString();
    case "id": {
      if (arg.isNull()) return "nil";
      if (ObjC.available) return new ObjC.Object(arg).toString();
      return arg.toString();
    }
    default:
      return arg.toString();
  }
}

function formatRetval(retval: NativePointer, type: string): string {
  if (type === "void") return "void";
  return formatArg(retval, type);
}

/**
 * Hook a native function by module and name.
 * @param module Module path (null for global/any module lookup)
 * @param name Function name
 * @param sig Optional type signature for argument/return logging
 */
export function hook(
  module: string | null,
  name: string,
  sig?: NativeHookSignature,
): void {
  // Check if already hooked
  {
    const functions = hooked.get(module);
    if (!functions) {
      hooked.set(module, new Map());
    } else if (functions.has(name)) {
      return;
    }
  }

  // Find the export
  const addr: NativePointer | null = module
    ? (Process.findModuleByName(module)?.findExportByName(name) ?? null)
    : getGlobalExport(name);

  if (!addr)
    throw new Error(`Export ${name} not found${module ? ` in ${module}` : ""}`);

  // Store signature for snapshot/restore
  if (sig) {
    if (!signatures.has(module)) signatures.set(module, new Map());
    signatures.get(module)!.set(name, sig);
  }

  const symbolName = module ? `${module}!${name}` : name;
  const listener = Interceptor.attach(addr, {
    onEnter(args) {
      let line = `${name}(`;
      const argParts: string[] = [];
      if (sig) {
        for (let i = 0; i < sig.args.length; i++) {
          argParts.push(`${sig.args[i]}: ${formatArg(args[i], sig.args[i])}`);
        }
      }
      line += argParts.join(", ") + ")";

      send({
        subject: "hook",
        category: "native",
        symbol: symbolName,
        dir: "enter",
        line,
        backtrace: bt(this.context),
        extra: { module, name },
      } satisfies BaseMessage);
    },
    onLeave(retval) {
      let line = `${name}()`;
      if (sig) {
        line += ` -> ${formatRetval(retval, sig.returns)}`;
      }

      send({
        subject: "hook",
        category: "native",
        symbol: symbolName,
        dir: "leave",
        line,
        backtrace: bt(this.context),
        extra: { module, name },
      } satisfies BaseMessage);
    },
  });

  hooked.get(module)!.set(name, listener);
}

/**
 * Unhook a native function.
 * @param module Module path (null for global lookup)
 * @param name Function name
 */
export function unhook(module: string | null, name: string): void {
  const functions = hooked.get(module);
  if (!functions) return;

  const listener = functions.get(name);
  if (!listener) return;

  listener.detach();
  functions.delete(name);

  if (functions.size === 0) {
    hooked.delete(module);
  }

  // Clean up stored signature
  const sigs = signatures.get(module);
  if (sigs) {
    sigs.delete(name);
    if (sigs.size === 0) signatures.delete(module);
  }
}

/**
 * List all active native hooks with optional signatures.
 */
export function list(): Array<{
  module: string | null;
  name: string;
  sig?: NativeHookSignature;
}> {
  const result: Array<{
    module: string | null;
    name: string;
    sig?: NativeHookSignature;
  }> = [];

  for (const [module, functions] of hooked) {
    for (const name of functions.keys()) {
      const sig = signatures.get(module)?.get(name);
      result.push({ module, name, sig });
    }
  }

  return result;
}
