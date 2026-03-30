import { execSync } from "node:child_process";
import { copyFile, mkdir } from "node:fs/promises";
import { join } from "node:path";

const run = (cmd: string, cwd?: string) =>
  execSync(cmd, { cwd, stdio: "inherit" });

// ensure submodules are initialized
run("git submodule update --init --recursive");

// sub-workspace dependencies (triggers their prepare hooks → build)
run("bun i", "./agent");
run("bun i", "./gui");

// radare2 WASM runtime
run("bun scripts/fetch-r2-wasm.ts");

// r2hermes WASM (hbc decompiler)
const wasmDist = "externals/radare/r2hermes.wasm/dist";
try {
  run("bun run setup", "externals/radare/r2hermes.wasm");
  run("bun run build", "externals/radare/r2hermes.wasm");
  await mkdir("gui/public", { recursive: true });
  await copyFile(join(wasmDist, "hbc.wasm"), "gui/public/hbc.wasm");
} catch {
  console.warn("\nwasi-sdk not available — skipping r2hermes WASM build.");
  console.warn("The HBC decompiler will not work until you build it:");
  console.warn("  cd externals/radare/r2hermes.wasm && bun run setup && bun run build\n");
}
