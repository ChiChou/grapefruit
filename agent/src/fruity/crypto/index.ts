import * as crypto from "./crypto.js";

const CRYPTO_GROUPS = ["cccrypt", "x509", "hash", "hmac"] as const;

let active = false;
let listeners: InvocationListener[] = [];

export function start(): void {
  if (active) return;
  for (const group of CRYPTO_GROUPS) {
    if (group === "cccrypt") {
      listeners.push(...crypto.cccrypt());
    } else if (group === "x509") {
      listeners.push(...crypto.x509());
    } else if (group === "hash") {
      listeners.push(...crypto.hash());
    } else if (group === "hmac") {
      listeners.push(...crypto.hmac());
    }
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
