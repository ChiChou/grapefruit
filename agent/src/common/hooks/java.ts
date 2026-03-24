import Java from "frida-java-bridge";

export function perform<T>(fn: () => T): T {
  let result!: T;
  let error: unknown;
  Java.perform(() => {
    try {
      result = fn();
    } catch (e) {
      error = e;
    }
  });
  if (error !== undefined) throw error;
  return result;
}

type AnyMethod = Java.MethodDispatcher | Java.Method;

export type HookCallback = (
  original: AnyMethod,
  self: Java.Wrapper,
  args: unknown[],
) => unknown;

export function hook(method: AnyMethod, fn: HookCallback): InvocationListener {
  const orig = method.implementation;
  method.implementation = function (this: Java.Wrapper, ...args: unknown[]) {
    return fn(method, this, args);
  };
  return {
    detach: () => {
      method.implementation = orig;
    },
  };
}

export function bt(limit = 16): string[] {
  try {
    const { frames } = Java.backtrace({ limit });
    return frames.map(
      (f) => `${f.className}.${f.methodName}(${f.fileName}:${f.lineNumber})`,
    );
  } catch {
    return [];
  }
}
