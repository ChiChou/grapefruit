import { accessSync, constants } from "node:fs";
import { delimiter, extname, join } from "node:path";
import { spawnSync } from "node:child_process";

export const npm = process.platform === "win32" ? "npm.cmd" : "npm";

export function tool(name: string) {
  const path = process.env.PATH?.split(delimiter) ?? [];
  const exts =
    process.platform === "win32" && !extname(name)
      ? (process.env.PATHEXT?.split(";") ?? [".COM", ".EXE", ".BAT", ".CMD"])
      : [""];

  for (const dir of path) {
    for (const ext of exts) {
      const file = join(dir, name + ext.toLowerCase());
      try {
        accessSync(file, process.platform === "win32" ? constants.F_OK : constants.X_OK);
        return file;
      } catch {}
    }
  }
}

export function run(argv: string[], cwd = process.cwd()) {
  const [command, ...args] = argv;
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
    shell: false,
  });

  if (result.error) throw result.error;
  if (result.status) {
    throw new Error(`${argv.join(" ")} exited with code ${result.status}`);
  }
}

export function need(name: string) {
  const file = tool(name);
  if (file) return file;
  throw new Error(`Unable to find ${name} on PATH`);
}
