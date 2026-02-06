import * as crypto from "./crypto.js";
import * as sqlite from "./sqlite.js";
import * as pasteboard from "./pasteboard.js";
import * as deviceid from "./deviceid.js";
import * as biometric from "./biometric.js";
import * as fileops from "./fileops.js";
import * as native from "@/common/hooks/native.js";
import * as objc from "./objc.js";

const active = new Map<string, InvocationListener[]>();

// Available hook groups
const HOOK_GROUPS = [
  "pasteboard",
  "fileops",
  "deviceid",
  "biometric",
  "sqlite",
  "crypto",
] as const;

function get(group: string) {
  if (group === "crypto") {
    return [
      ...crypto.cccrypt(),
      ...crypto.x509(),
      ...crypto.hmac(),
      ...crypto.hash(),
    ];
  } else if (group === "sqlite") {
    return [
      ...sqlite.open(),
      ...sqlite.bind(),
      ...sqlite.prepare(),
      ...sqlite.exec(),
    ];
  } else if (group === "pasteboard") {
    return [...pasteboard.monitor()];
  } else if (group === "deviceid") {
    return [...deviceid.spoof()];
  } else if (group === "biometric") {
    return [...biometric.bypass()];
  } else if (group === "fileops") {
    return [...fileops.monitor()];
  }
}

/**
 * Get the list of available hook groups
 */
export function list(): string[] {
  return [...HOOK_GROUPS];
}

/**
 * Get the status of all hook groups
 */
export function status(): Record<string, boolean> {
  const result: Record<string, boolean> = {};
  for (const group of HOOK_GROUPS) {
    result[group] = active.has(group);
  }
  return result;
}

export function start(group: string) {
  if (active.has(group)) return;
  const hooks = get(group);
  if (!hooks) return;
  active.set(group, hooks);
}

export function stop(group: string) {
  const hooks = active.get(group);
  if (!hooks) return;
  for (const hook of hooks) {
    hook.detach();
  }
  active.delete(group);
}

/**
 * User hook type definition
 */
export interface UserHook {
  type: "objc" | "native";
  module?: string | null;
  cls?: string;
  name: string;
}

/**
 * Get all user-defined hooks (both ObjC and native)
 */
export function userHooks(): UserHook[] {
  const result: UserHook[] = [];

  // Add ObjC hooks
  for (const { cls, sel } of objc.list()) {
    result.push({
      type: "objc",
      cls,
      name: sel,
    });
  }

  // Add native hooks
  for (const { module, name } of native.list()) {
    result.push({
      type: "native",
      module,
      name,
    });
  }

  return result;
}
