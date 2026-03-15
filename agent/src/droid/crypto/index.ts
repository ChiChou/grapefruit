import * as crypto from "./crypto.js";

const CRYPTO_GROUPS = ["cipher", "pbkdf", "keygen"] as const;

let active = false;
let listeners: InvocationListener[] = [];

export function start(): void {
  if (active) return;
  for (const group of CRYPTO_GROUPS) {
    if (group === "cipher") listeners.push(...crypto.cipher());
    if (group === "pbkdf") listeners.push(...crypto.pbkdf());
    if (group === "keygen") listeners.push(...crypto.keygen());
  }
  active = true;
}

export function stop(): void {
  if (!active) return;
  for (const hook of listeners) {
    hook.detach();
  }
  listeners = [];
  active = false;
}

export function status(): boolean {
  return active;
}

export function available(): boolean {
  return true;
}
