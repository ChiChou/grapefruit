import * as preferences from "./preferences.ts";
import type { TapRule } from "@agent/common/taps";

export function createTapStore(deviceId: string, identifier: string) {
  const key = `taps:${deviceId}|${identifier}`;
  return {
    save(rules: TapRule[]): void {
      preferences.set(key, rules);
    },
    load(): TapRule[] | null {
      return preferences.get(key) as TapRule[] | null;
    },
    clear(): void {
      preferences.rm(key);
    },
  };
}
