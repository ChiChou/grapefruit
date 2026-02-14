import * as crypto from "./crypto.js";

const active = new Map<string, InvocationListener[]>();

const CRYPTO_GROUPS = ["cccrypt", "x509", "hash", "hmac"] as const;

function get(group: string) {
  if (group === "cccrypt") {
    return [...crypto.cccrypt()];
  } else if (group === "x509") {
    return [...crypto.x509()];
  } else if (group === "hash") {
    return [...crypto.hash()];
  } else if (group === "hmac") {
    return [...crypto.hmac()];
  }
}

export function list(): string[] {
  return [...CRYPTO_GROUPS];
}

export function status(): Record<string, boolean> {
  const result: Record<string, boolean> = {};
  for (const group of CRYPTO_GROUPS) {
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
