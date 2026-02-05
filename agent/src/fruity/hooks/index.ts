import * as crypto from "./crypto.js";
import * as sqlite from "./sqlite.js";

const active = new Map<string, InvocationListener[]>();

// Available hook groups
const HOOK_GROUPS = ["crypto", "sqlite"] as const;

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
