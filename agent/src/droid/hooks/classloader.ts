import Java from "frida-java-bridge";
import type { BaseMessage } from "@/common/hooks/context.js";
import { hook, bt } from "@/common/hooks/java.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "classloader";
  extra?: {
    dexPath?: string;
    command?: string;
    untrusted: boolean;
    risk: "critical" | "high" | "medium";
  };
}

const UNTRUSTED_PATHS = [
  "/sdcard",
  "/storage/emulated",
  "/download",
  "/tmp",
  "/data/local/tmp",
];

function isUntrustedPath(path: string): boolean {
  const lower = path.toLowerCase();
  return UNTRUSTED_PATHS.some((p) => lower.includes(p));
}

function riskLevel(untrusted: boolean, isInMemory?: boolean): "critical" | "high" | "medium" {
  if (isInMemory) return "critical";
  if (untrusted) return "critical";
  return "medium";
}

const hooks: InvocationListener[] = [];

// ── DexClassLoader ──────────────────────────────────────────────────────

function hookDexClassLoader() {
  const DexClassLoader = Java.use("dalvik.system.DexClassLoader");

  const init = DexClassLoader.$init.overload(
    "java.lang.String",
    "java.lang.String",
    "java.lang.String",
    "java.lang.ClassLoader",
  );

  hooks.push(hook(init, (original, self, args) => {
    const dexPath = args[0] ? String(args[0]) : "";
    const untrusted = isUntrustedPath(dexPath);
    const risk = riskLevel(untrusted);
    const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

    const msg: Message = {
      subject: "hook",
      category: "classloader",
      symbol: "DexClassLoader.$init",
      dir: "enter",
      line: `DexClassLoader("${dexPath}")${warning}`,
      backtrace: bt(),
      extra: { dexPath, untrusted, risk },
    };
    send(msg);

    return original.call(self, ...args);
  }));
}

// ── PathClassLoader ─────────────────────────────────────────────────────

function hookPathClassLoader() {
  const PathClassLoader = Java.use("dalvik.system.PathClassLoader");

  // overload(String, ClassLoader)
  try {
    const init2 = PathClassLoader.$init.overload(
      "java.lang.String",
      "java.lang.ClassLoader",
    );
    hooks.push(hook(init2, (original, self, args) => {
      const dexPath = args[0] ? String(args[0]) : "";
      const untrusted = isUntrustedPath(dexPath);
      const risk = riskLevel(untrusted);
      const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

      send({
        subject: "hook",
        category: "classloader",
        symbol: "PathClassLoader.$init",
        dir: "enter",
        line: `PathClassLoader("${dexPath}")${warning}`,
        backtrace: bt(),
        extra: { dexPath, untrusted, risk },
      } as Message);

      return original.call(self, ...args);
    }));
  } catch (e) {
    console.warn("classloader: PathClassLoader(String, ClassLoader) overload unavailable:", e);
  }

  // overload(String, String, ClassLoader)
  try {
    const init3 = PathClassLoader.$init.overload(
      "java.lang.String",
      "java.lang.String",
      "java.lang.ClassLoader",
    );
    hooks.push(hook(init3, (original, self, args) => {
      const dexPath = args[0] ? String(args[0]) : "";
      const untrusted = isUntrustedPath(dexPath);
      const risk = riskLevel(untrusted);
      const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

      send({
        subject: "hook",
        category: "classloader",
        symbol: "PathClassLoader.$init",
        dir: "enter",
        line: `PathClassLoader("${dexPath}")${warning}`,
        backtrace: bt(),
        extra: { dexPath, untrusted, risk },
      } as Message);

      return original.call(self, ...args);
    }));
  } catch (e) {
    console.warn("classloader: PathClassLoader(String, String, ClassLoader) overload unavailable:", e);
  }
}

// ── InMemoryDexClassLoader (API 26+) ────────────────────────────────────

function hookInMemoryDexClassLoader() {
  const InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");

  // overload(ByteBuffer, ClassLoader)
  try {
    const init = InMemoryDexClassLoader.$init.overload(
      "java.nio.ByteBuffer",
      "java.lang.ClassLoader",
    );
    hooks.push(hook(init, (original, self, args) => {
      const size = args[0] ? (args[0] as Java.Wrapper).capacity() : 0;

      send({
        subject: "hook",
        category: "classloader",
        symbol: "InMemoryDexClassLoader.$init",
        dir: "enter",
        line: `InMemoryDexClassLoader(ByteBuffer[${size}]) \u26a0\ufe0f In-memory DEX`,
        backtrace: bt(),
        extra: { dexPath: "<in-memory>", untrusted: true, risk: "critical" },
      } as Message);

      return original.call(self, ...args);
    }));
  } catch (e) {
    console.warn("classloader: InMemoryDexClassLoader(ByteBuffer, ClassLoader) overload unavailable:", e);
  }

  // overload(ByteBuffer[], ClassLoader)
  try {
    const init2 = InMemoryDexClassLoader.$init.overload(
      "[Ljava.nio.ByteBuffer;",
      "java.lang.ClassLoader",
    );
    hooks.push(hook(init2, (original, self, args) => {
      const count = args[0] ? (args[0] as Java.Wrapper).length : 0;

      send({
        subject: "hook",
        category: "classloader",
        symbol: "InMemoryDexClassLoader.$init",
        dir: "enter",
        line: `InMemoryDexClassLoader(ByteBuffer[${count} buffers]) \u26a0\ufe0f In-memory DEX`,
        backtrace: bt(),
        extra: { dexPath: "<in-memory>", untrusted: true, risk: "critical" },
      } as Message);

      return original.call(self, ...args);
    }));
  } catch (e) {
    console.warn("classloader: InMemoryDexClassLoader(ByteBuffer[], ClassLoader) overload unavailable:", e);
  }
}

// ── BaseDexClassLoader ──────────────────────────────────────────────────

function hookBaseDexClassLoader() {
  const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");

  const init = BaseDexClassLoader.$init.overload(
    "java.lang.String",
    "java.io.File",
    "java.lang.String",
    "java.lang.ClassLoader",
  );

  hooks.push(hook(init, (original, self, args) => {
    const dexPath = args[0] ? String(args[0]) : "";
    const untrusted = isUntrustedPath(dexPath);
    const risk = riskLevel(untrusted);
    const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

    send({
      subject: "hook",
      category: "classloader",
      symbol: "BaseDexClassLoader.$init",
      dir: "enter",
      line: `BaseDexClassLoader("${dexPath}")${warning}`,
      backtrace: bt(),
      extra: { dexPath, untrusted, risk },
    } as Message);

    return original.call(self, ...args);
  }));
}

// ── DexFile.loadDex (deprecated but still used) ─────────────────────────

function hookDexFile() {
  const DexFile = Java.use("dalvik.system.DexFile");

  const loadDex = DexFile.loadDex.overload(
    "java.lang.String",
    "java.lang.String",
    "int",
  );

  hooks.push(hook(loadDex, (original, self, args) => {
    const sourcePath = args[0] ? String(args[0]) : "";
    const outputPath = args[1] ? String(args[1]) : "";
    const untrusted = isUntrustedPath(sourcePath) || isUntrustedPath(outputPath);
    const risk = riskLevel(untrusted);
    const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

    send({
      subject: "hook",
      category: "classloader",
      symbol: "DexFile.loadDex",
      dir: "enter",
      line: `DexFile.loadDex("${sourcePath}", "${outputPath}")${warning}`,
      backtrace: bt(),
      extra: { dexPath: sourcePath, untrusted, risk },
    } as Message);

    return original.call(self, ...args);
  }));
}

// ── Runtime.exec ────────────────────────────────────────────────────────

function hookRuntimeExec() {
  const Runtime = Java.use("java.lang.Runtime");

  // exec(String)
  try {
    const execStr = Runtime.exec.overload("java.lang.String");
    hooks.push(hook(execStr, (original, self, args) => {
      const command = args[0] ? String(args[0]) : "";
      const untrusted = isUntrustedPath(command);
      const risk: "critical" | "high" | "medium" = untrusted ? "critical" : "high";
      const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

      send({
        subject: "hook",
        category: "classloader",
        symbol: "Runtime.exec",
        dir: "enter",
        line: `Runtime.exec("${command}")${warning}`,
        backtrace: bt(),
        extra: { command, untrusted, risk },
      } as Message);

      return original.call(self, ...args);
    }));
  } catch (e) {
    console.warn("classloader: Runtime.exec(String) overload unavailable:", e);
  }

  // exec(String[])
  try {
    const execArr = Runtime.exec.overload("[Ljava.lang.String;");
    hooks.push(hook(execArr, (original, self, args) => {
      const cmdArray = args[0] as Java.Wrapper | null;
      const parts: string[] = [];
      if (cmdArray) {
        for (let i = 0; i < cmdArray.length; i++) {
          parts.push(String(cmdArray[i]));
        }
      }
      const command = parts.join(" ");
      const untrusted = isUntrustedPath(command);
      const risk: "critical" | "high" | "medium" = untrusted ? "critical" : "high";
      const warning = untrusted ? " \u26a0\ufe0f Untrusted path" : "";

      send({
        subject: "hook",
        category: "classloader",
        symbol: "Runtime.exec",
        dir: "enter",
        line: `Runtime.exec(${JSON.stringify(parts)})${warning}`,
        backtrace: bt(),
        extra: { command, untrusted, risk },
      } as Message);

      return original.call(self, ...args);
    }));
  } catch (e) {
    console.warn("classloader: Runtime.exec(String[]) overload unavailable:", e);
  }
}

// ── Lifecycle ───────────────────────────────────────────────────────────

let running = false;

export function available(): boolean {
  if (!Java.available) return false;
  let found = false;
  Java.perform(() => {
    try {
      Java.use("dalvik.system.DexClassLoader");
      found = true;
    } catch {
      /* not found */
    }
  });
  return found;
}

export function status(): boolean {
  return running;
}

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    try { hookDexClassLoader(); } catch (e) { console.warn("classloader: DexClassLoader hooks unavailable:", e); }
    try { hookPathClassLoader(); } catch (e) { console.warn("classloader: PathClassLoader hooks unavailable:", e); }
    try { hookInMemoryDexClassLoader(); } catch (e) { console.warn("classloader: InMemoryDexClassLoader hooks unavailable:", e); }
    try { hookBaseDexClassLoader(); } catch (e) { console.warn("classloader: BaseDexClassLoader hooks unavailable:", e); }
    try { hookDexFile(); } catch (e) { console.warn("classloader: DexFile hooks unavailable:", e); }
    try { hookRuntimeExec(); } catch (e) { console.warn("classloader: Runtime.exec hooks unavailable:", e); }
  });
}

export function stop() {
  if (!running) return;
  running = false;

  for (const h of hooks) {
    try { h.detach(); } catch { /* class may have been unloaded */ }
  }
  hooks.length = 0;
}
