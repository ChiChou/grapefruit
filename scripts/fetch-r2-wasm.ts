/**
 * Download the radare2 WASI API build (pinned version).
 *
 * Usage: bun scripts/fetch-r2-wasm.ts
 *
 * The WASM binary is placed at the project root as radare2.wasm.
 * CI caches this file by the version key below.
 */

import { existsSync } from "node:fs";
import { createHash } from "node:crypto";
import { readFile, unlink, rename, rm } from "node:fs/promises";
import { join } from "node:path";

const isWin = process.platform === "win32";

const R2_VERSION = "6.1.2";
const R2_SHA256 =
  "3436ba89d8263418718bcce657fc2316bac18e4d91c9b8228f4c00d01e2c7c4c";

const WASM_URL = `https://github.com/radareorg/radare2/releases/download/${R2_VERSION}/radare2-${R2_VERSION}-wasi-api.zip`;
const OUTPUT = "radare2.wasm";

async function main() {
  if (existsSync(OUTPUT)) {
    console.log(`[r2-wasm] ${OUTPUT} already exists, verifying...`);
    const hash = createHash("sha256")
      .update(await readFile(OUTPUT))
      .digest("hex");
    if (hash === R2_SHA256) {
      console.log("[r2-wasm] checksum OK, skipping download.");
      return;
    }
    console.log("[r2-wasm] checksum mismatch, re-downloading...");
  }

  console.log(`[r2-wasm] downloading radare2 ${R2_VERSION} WASI API build...`);
  const zipPath = `radare2-wasi-${R2_VERSION}.zip`;

  const res = await fetch(WASM_URL);
  if (!res.ok) throw new Error(`[r2-wasm] download failed: ${res.status} ${res.statusText}`);
  await Bun.write(zipPath, res);

  const innerDir = `radare2-${R2_VERSION}-wasi-api`;
  const zipEntry = `${innerDir}/radare2.wasm`; // zip entry path always uses forward slashes
  const tmpDir = "radare2-wasi-tmp";

  if (isWin) {
    await Bun.$`powershell -Command Expand-Archive -Force ${zipPath} -DestinationPath ${tmpDir}`;
  } else {
    await Bun.$`unzip -o ${zipPath} ${zipEntry} -d ${tmpDir}`;
  }

  await rename(join(tmpDir, innerDir, "radare2.wasm"), OUTPUT);
  await rm(tmpDir, { recursive: true, force: true });
  await unlink(zipPath);

  const hash = createHash("sha256")
    .update(await readFile(OUTPUT))
    .digest("hex");

  if (hash !== R2_SHA256) {
    console.error(`[r2-wasm] SHA256 mismatch!\n  expected: ${R2_SHA256}\n  got:      ${hash}`);
    console.error("[r2-wasm] Updating hash in script — verify this is expected.");
  }

  console.log(`[r2-wasm] ${OUTPUT} ready (${R2_VERSION}).`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
