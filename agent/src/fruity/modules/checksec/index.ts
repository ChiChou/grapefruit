import checksec, { type MachOResult } from "./macho.js";

export function all() {
  return Process.enumerateModules().map((mod) => checksec(mod));
}

export function single(name: string): MachOResult | undefined {
  const mod = Process.enumerateModules().find((mod) => mod.name === name);
  return mod ? checksec(mod) : undefined;
}

export function main() {
  return checksec(Process.mainModule);
}
