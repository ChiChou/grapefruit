import { mkdir, copyFile } from "node:fs/promises";
import { execSync } from "node:child_process";

await mkdir("./agent/dist", { recursive: true });
await mkdir("./gui/public", { recursive: true });

execSync(`bun i`, { cwd: "./agent", stdio: "inherit" });
execSync(`bun i`, { cwd: "./gui", stdio: "inherit" });
execSync(`bun scripts/fetch-r2-wasm.ts`, { stdio: "inherit" });
execSync(`bun run build`, { cwd: "./externals/radare/r2hermes.wasm", stdio: "inherit" });

// Copy hbc.wasm to gui public for Vite static serving
await copyFile("./externals/radare/r2hermes.wasm/dist/hbc.wasm", "./gui/public/hbc.wasm");
