const namespaces = new Set(["script", "memory", "threads", "symbol"]);

const methods = new Set([
  "info.processInfo",
  "webview.evaluate",
  "jsc.run",
  "rn.inject",
]);

export function check(ns: string, method: string): void {
  const spec = `${ns}.${method}`;
  if (spec === "symbol.strings") return;
  if (namespaces.has(ns) || methods.has(spec)) {
    throw new Error(
      `${spec} is not part of the IGF CLI. Use Frida directly for scripting and runtime primitives; use IGF for platform inspection and managed captures.`,
    );
  }
}
