import { createNative } from "@/common/hooks/group.js";
import * as crypto from "./crypto.js";

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

const { list, status, start, stop } = createNative(CRYPTO_GROUPS, get);
export { list, status, start, stop };
