import checksec, { type ELFResult } from "./elf.js";

export function all() {
  return Process.enumerateModules().map((mod) => checksec(mod));
}

export function single(name: string): ELFResult | undefined {
  const mod = Process.enumerateModules().find((mod) => mod.name === name);
  return mod ? checksec(mod) : undefined;
}
