import checksec, { type ELFResult } from "./elf.js";

export type ELFModuleResult = ELFResult & { name: string; path: string };

export function all(): ELFModuleResult[] {
  return Process.enumerateModules()
    .filter(
      (mod) =>
        mod.path.startsWith("/data/app") &&
        !mod.path.endsWith(".odex") &&
        !mod.path.endsWith(".oat"),
    )
    .map((mod) => ({ name: mod.name, path: mod.path, ...checksec(mod) }));
}

export function single(name: string): ELFResult | undefined {
  const mod = Process.enumerateModules().find((mod) => mod.name === name);
  return mod ? checksec(mod) : undefined;
}
