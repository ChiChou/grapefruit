import type { TapInfo, TapRule } from "@/common/taps.js";

import * as flutter from "./observers/flutter.js";
import * as jni from "./observers/jni.js";

interface TapEntry {
  start(): void;
  stop(): void;
  status(): boolean;
  available(): boolean;
}

const registry = new Map<string, TapEntry>();

registry.set("flutter", flutter);
registry.set("jni", jni);

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

  for (const [id, entry] of registry) {
    if (entry.status()) {
      rules.push({ type: "builtin", id });
    }
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
      }
    } catch (e) {
      console.warn(`taps: failed to restore rule ${JSON.stringify(rule)}:`, e);
    }
  }
}
