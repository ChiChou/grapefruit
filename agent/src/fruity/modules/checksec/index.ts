import checksec, { type MachOResult } from "./macho.js";

export type MachOModuleResult = MachOResult & { name: string; path: string };

export function all(): MachOModuleResult[] {
  return Process.enumerateModules()
    .filter((mod) => mod.path.startsWith("/private/var/"))
    .map((mod) => ({
      name: mod.name,
      path: mod.path,
      ...checksec(mod),
    }));
}

export function single(name: string): MachOResult | undefined {
  const mod = Process.enumerateModules().find((mod) => mod.name === name);
  return mod ? checksec(mod) : undefined;
}

export function main() {
  return checksec(Process.mainModule);
}
