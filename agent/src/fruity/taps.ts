import type { TapInfo, TapRule } from "@/common/taps.js";

import * as hookGroup from "./hooks/index.js";
import * as nsurl from "./observers/url/index.js";
import * as flutter from "./observers/flutter.js";
import * as objc from "./hooks/objc.js";
import * as native from "@/common/hooks/native.js";

interface TapEntry {
  start(): void;
  stop(): void;
  status(): boolean;
  available(): boolean;
}

const BUILTIN_GROUPS = [
  "sqlite",
  "pasteboard",
  "deviceid",
  "biometric",
  "fileops",
] as const;

const registry = new Map<string, TapEntry>();

// Register built-in hook groups
for (const id of BUILTIN_GROUPS) {
  registry.set(id, {
    start: () => hookGroup.start(id),
    stop: () => hookGroup.stop(id),
    status: () => hookGroup.status()[id] ?? false,
    available: () => true,
  });
}

registry.set("nsurl", nsurl);
registry.set("flutter", flutter);

export function list(): TapInfo[] {
  const result: TapInfo[] = [];
  for (const [id, entry] of registry) {
    result.push({
      id,
      active: entry.status(),
      available: entry.available(),
    });
  }
  return result;
}

export function start(id: string): void {
  const entry = registry.get(id);
  if (!entry) throw new Error(`Unknown tap: ${id}`);
  entry.start();
}

export function stop(id: string): void {
  const entry = registry.get(id);
  if (!entry) throw new Error(`Unknown tap: ${id}`);
  entry.stop();
}

export function snapshot(): TapRule[] {
  const rules: TapRule[] = [];

  // Collect active built-in taps
  for (const [id, entry] of registry) {
    if (entry.status()) {
      rules.push({ type: "builtin", id });
    }
  }

  // Collect active user-defined ObjC hooks
  for (const { cls, sel } of objc.list()) {
    rules.push({ type: "objc", cls, sel });
  }

  // Collect active user-defined native hooks
  for (const { module, name } of native.list()) {
    rules.push({ type: "native", module, name });
  }

  return rules;
}

export function restore(rules: TapRule[]): void {
  for (const rule of rules) {
    try {
      switch (rule.type) {
        case "builtin":
          start(rule.id);
          break;
        case "objc":
          objc.swizzle(rule.cls, rule.sel);
          break;
        case "native":
          native.hook(rule.module, rule.name);
          break;
      }
    } catch (e) {
      console.warn(`taps: failed to restore rule ${JSON.stringify(rule)}:`, e);
    }
  }
}
