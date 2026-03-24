/**
 * Downloads r2.mjs + r2.wasm from @frida/react-use-r2 npm tarball.
 *
 * These are Emscripten-compiled radare2 WASM assets with custom r2_open/r2_execute
 * entry points and on-demand memory read callbacks (LGPLv3, source: radare2).
 *
 * The React hook wrapper lives in externals/react-use-r2 (MIT).
 */
import { existsSync } from "node:fs";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { execSync } from "node:child_process";
import { join } from "node:path";

const PKG = "@frida/react-use-r2";
const OUT_DIR = join(import.meta.dirname, "..", "public");
const MARKER = join(OUT_DIR, "r2.wasm");

async function main() {
  if (existsSync(MARKER)) {
    console.log("[r2] already present, skipping");
    return;
  }

  await mkdir(OUT_DIR, { recursive: true });

  console.log(`[r2] fetching tarball URL for ${PKG}...`);
  const meta = await fetch(`https://registry.npmjs.org/${PKG}/latest`).then(
    (r) => r.json(),
  );
  const tarballUrl = meta.dist?.tarball as string;
  if (!tarballUrl) throw new Error("Could not resolve tarball URL");

  console.log(`[r2] downloading ${tarballUrl}...`);
  const tmp = join(OUT_DIR, "_r2.tgz");
  const buf = await fetch(tarballUrl).then((r) => r.arrayBuffer());
  await writeFile(tmp, new Uint8Array(buf));

  execSync(
    `tar xzf "${tmp}" --strip-components=2 -C "${OUT_DIR}" package/dist/r2.mjs package/dist/r2.wasm`,
    { stdio: "inherit" },
  );
  await rm(tmp);

  if (!existsSync(MARKER)) {
    throw new Error("r2.wasm not found after extraction");
  }

  console.log("[r2] done");
}

main().catch((e) => {
  console.error("[r2]", e);
  process.exit(1);
});
