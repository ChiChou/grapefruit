import * as preferences from "./preferences.ts";
import type { PinRule } from "@agent/common/pins";

export function createPinStore(deviceId: string, identifier: string) {
  const key = `pins:${deviceId}|${identifier}`;
  return {
    save(rules: PinRule[]): void {
      preferences.set(key, rules);
    },
    load(): PinRule[] | null {
      return preferences.get(key) as PinRule[] | null;
    },
    clear(): void {
      preferences.rm(key);
    },
  };
}
