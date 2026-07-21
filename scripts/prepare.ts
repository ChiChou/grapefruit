import { spawnSync } from "node:child_process";
import { copyFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { npm } from "./lib.ts";

const root = join(import.meta.dirname, "..");

function run(cmd: string[], cwd = root) {
  const [command, ...args] = cmd;
  const result = spawnSync(command, args, {
    cwd,
    stdio: "inherit",
    shell: false,
  });

  if (result.error) throw result.error;
  if (result.status) {
    throw new Error(`${cmd.join(" ")} exited with code ${result.status}`);
  }
}

function prebuild(pkg: string) {
  run(
    [
      process.execPath,
      join(root, "node_modules", "prebuild-install", "bin.js"),
      "-r",
      "napi",
    ],
    join(root, "node_modules", pkg),
  );
}

// ensure submodules are initialized
run(["git", "submodule", "update", "--init", "--recursive"]);

// all workspace dependencies
run([npm, "install"]);
prebuild("frida");
prebuild("frida16");
run([npm, "install"], join(root, "agent"));
run([npm, "install"], join(root, "gui"));

// radare2 WASM runtime
run([process.execPath, "scripts/fetch-r2-wasm.ts"]);

// r2hermes WASM (hbc decompiler)
const wasmDist = "externals/radare/r2hermes.wasm/dist";
const hbc = join(root, "externals", "radare", "r2hermes.wasm");
try {
  run([npm, "run", "setup"], hbc);
  run([npm, "run", "build"], hbc);
  await mkdir(join(root, "gui", "public"), { recursive: true });
  await copyFile(
    join(root, wasmDist, "hbc.wasm"),
    join(root, "gui", "public", "hbc.wasm"),
  );
} catch {
  console.warn("\nwasi-sdk not available — skipping r2hermes WASM build.");
  console.warn("The HBC decompiler will not work until you build it:");
  console.warn(
    "  cd externals/radare/r2hermes.wasm && npm run setup && npm run build\n",
  );
}
