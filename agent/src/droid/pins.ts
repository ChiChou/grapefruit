import type { PinInfo, PinRule } from "@/common/pins.js";

import * as hookGroup from "./hooks/index.js";
import * as crypto from "./hooks/crypto/index.js";
import * as flutter from "./hooks/flutter.js";
import * as jni from "./hooks/jni.js";
import * as privacy from "./hooks/privacy/index.js";
import * as http from "./hooks/http/common.js";

interface PinEntry {
  start(): void;
  stop(): void;
  status(): boolean;
  available(): boolean;
}

const BUILTIN_GROUPS = [
  "clipboard",
  "broadcast",
  "intent",
  "sharedpref",
  "pendingintent",
  "sslpinning",
] as const;

const registry = new Map<string, PinEntry>();

for (const id of BUILTIN_GROUPS) {
  registry.set(id, {
    start: () => hookGroup.start(id),
    stop: () => hookGroup.stop(id),
    status: () => hookGroup.status()[id] ?? false,
    available: () => true,
  });
}

registry.set("crypto", crypto);
registry.set("flutter", flutter);
registry.set("jni", jni);
registry.set("privacy", privacy);
registry.set("http", http);

export function list(): PinInfo[] {
  const result: PinInfo[] = [];
  for (const [id, entry] of registry) {
    result.push({
      id,
      active: entry.status(),
      available: entry.available(),
    });
  }
  return result;
}

function resolve(id: string): PinEntry {
  const entry = registry.get(id);
  if (!entry) throw new Error(`Unknown pin: ${id}`);
  return entry;
}

export function active(id: string): boolean {
  return resolve(id).status();
}

export function available(id: string): boolean {
  return resolve(id).available();
}

export function start(id: string): void {
  resolve(id).start();
}

export function stop(id: string): void {
  resolve(id).stop();
}

export function snapshot(): PinRule[] {
  const rules: PinRule[] = [];

  for (const [id, entry] of registry) {
    if (entry.status()) {
      rules.push({ type: "builtin", id });
    }
  }

  return rules;
}

export function restore(rules: PinRule[]): void {
  for (const rule of rules) {
    try {
      switch (rule.type) {
        case "builtin":
          start(rule.id);
          break;
      }
    } catch (e) {
      console.warn(`pins: failed to restore rule ${JSON.stringify(rule)}:`, e);
    }
  }
}
