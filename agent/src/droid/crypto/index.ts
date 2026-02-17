import { createHookGroup } from "@/common/hook-group.js";
import * as crypto from "./crypto.js";

const CRYPTO_GROUPS = ["cipher", "pbkdf", "keygen"] as const;

function get(group: string) {
  if (group === "cipher") return [...crypto.cipher()];
  if (group === "pbkdf") return [...crypto.pbkdf()];
  if (group === "keygen") return [...crypto.keygen()];
}

const { list, status, start, stop } = createHookGroup(CRYPTO_GROUPS, get);
export { list, status, start, stop };
