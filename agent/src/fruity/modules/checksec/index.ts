import checksec, { type MachOResult } from "./macho.js";

export { securityConfig, type SecurityConfig } from "./secconfig.js";
export type MachOModuleResult = MachOResult & {
  name: string;
  path: string;
  isMain: boolean;
};

export function all(): MachOModuleResult[] {
  const main = Process.mainModule;
  return Process.enumerateModules()
    .filter(
      (mod) => mod.base.equals(main.base) || mod.path.startsWith("/private/var/"),
    )
    .map((mod) => ({
      name: mod.name,
      path: mod.path,
      isMain: mod.base.equals(main.base),
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
