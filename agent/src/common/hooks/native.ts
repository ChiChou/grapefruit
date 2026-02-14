import { BaseMessage, bt } from "./context.js";

const hooked = new Map<string | null, Map<string, InvocationListener>>();

/**
 * Hook a native function by module and name.
 * @param module Module path (null for global/any module lookup)
 * @param name Function name
 */
export function hook(module: string | null, name: string): void {
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
  let addr: NativePointer | null = null;
  if (module) {
    const mod = Process.findModuleByName(module);
    if (mod) {
      addr = mod.findExportByName(name);
    }
  } else {
    // Search all modules for the export
    for (const mod of Process.enumerateModules()) {
      addr = mod.findExportByName(name);
      if (addr) break;
    }
  }
  if (!addr) {
    throw new Error(`Export ${name} not found${module ? ` in ${module}` : ""}`);
  }

  const symbolName = module ? `${module}!${name}` : name;
  const listener = Interceptor.attach(addr, {
    onEnter(args) {
      send({
        subject: "hook",
        category: "native",
        symbol: symbolName,
        dir: "enter",
        line: `${name}() // enter`,
        backtrace: bt(this.context),
        extra: { module, name },
      } satisfies BaseMessage);
    },
    onLeave(retval) {
      send({
        subject: "hook",
        category: "native",
        symbol: symbolName,
        dir: "leave",
        line: `${name}() // leave`,
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
}

/**
 * List all active native hooks.
 */
export function list(): Array<{ module: string | null; name: string }> {
  const result: Array<{ module: string | null; name: string }> = [];

  for (const [module, functions] of hooked) {
    for (const name of functions.keys()) {
      result.push({ module, name });
    }
  }

  return result;
}
