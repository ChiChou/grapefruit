import { encryptionInfo, pie } from "../lib/macho.js";

export interface CheckSecFlags {
  pie: boolean;
  arc: boolean;
  canary: boolean;
  encrypted: boolean;
}

export function flags(): CheckSecFlags {
  const [main] = Process.enumerateModules();
  const uniqueNames = new Set(main.enumerateImports().map(({ name }) => name));

  return {
    pie: pie(main),
    arc: uniqueNames.has("objc_release"),
    canary: uniqueNames.has("__stack_chk_guard"),
    encrypted: encryptionInfo(main)?.cryptid === 1,
  };
}
