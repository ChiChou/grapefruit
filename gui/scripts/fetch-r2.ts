/**
 * Downloads r2.mjs + r2.wasm from @frida/react-use-r2 via unpkg.
 *
 * These are Emscripten-compiled radare2 WASM assets with custom r2_open/r2_execute
 * entry points and on-demand memory read callbacks (LGPLv3, source: radare2).
 *
 * The React hook wrapper lives in externals/react-use-r2 (MIT).
 */
import { access, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const PKG = "@frida/react-use-r2";
const VERSION = "2.0.0";
const OUT_DIR = join(import.meta.dirname, "..", "public");
const MARKER = join(OUT_DIR, "r2.wasm");

const FILES = ["dist/r2.mjs", "dist/r2.wasm"] as const;

async function main() {
  if (await access(MARKER).then(() => true, () => false)) {
    console.log("[r2] already present, skipping");
    return;
  }

  await mkdir(OUT_DIR, { recursive: true });

  await Promise.all(
    FILES.map(async (file) => {
      const url = `https://unpkg.com/${PKG}@${VERSION}/${file}`;
      const dest = join(OUT_DIR, file.split("/").pop()!);
      console.log(`[r2] fetching ${url}...`);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
      await writeFile(dest, new Uint8Array(await res.arrayBuffer()));
    }),
  );

  await access(MARKER).catch(() => {
    throw new Error("r2.wasm not found after download");
  });

  console.log("[r2] done");
}

main().catch((e) => {
  console.error("[r2]", e);
  process.exit(1);
});
