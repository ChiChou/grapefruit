import Java from "frida-java-bridge";

export function perform<T>(fn: () => T): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    Java.perform(() => {
      try {
        resolve(fn());
      } catch (e) {
        reject(e);
      }
    });
  });
}

export function patch(restores: Array<() => void>) {
  return function apply(
    method: Java.MethodDispatcher,
    fn: (original: Java.MethodDispatcher, self: Java.Wrapper, args: unknown[]) => unknown,
  ) {
    const orig = method.implementation;
    method.implementation = function (this: Java.Wrapper, ...args: unknown[]) {
      return fn(method, this, args);
    };
    restores.push(() => {
      method.implementation = orig;
    });
  };
}

export function hook(
  cls: Java.Wrapper,
  method: string,
  overload: string[],
  impl: Java.MethodImplementation,
): InvocationListener {
  const m = cls[method].overload(...overload);
  m.implementation = impl;
  return {
    detach: () => {
      m.implementation = null;
    },
  };
}

export function backtrace(): string[] {
  try {
    const sw = Java.use("java.io.StringWriter").$new();
    const pw = Java.use("java.io.PrintWriter").$new(sw);
    Java.use("java.lang.Throwable").$new().printStackTrace(pw);
    return sw
      .toString()
      .split("\n")
      .slice(2, 12)
      .map((l: string) => l.trim());
  } catch {
    return [];
  }
}
