import { mkdir } from "node:fs/promises";
import { execSync } from "node:child_process";

const resolve = (relative: string) =>
  new URL(relative, import.meta.url).pathname;

await mkdir(resolve("../agent/dist"), { recursive: true });

execSync(`bun i`, { cwd: resolve("../agent"), stdio: "inherit" });
execSync(`bun i`, { cwd: resolve("../gui"), stdio: "inherit" });
