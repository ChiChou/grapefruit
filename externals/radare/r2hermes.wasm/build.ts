/**
 * Cross-platform build script for r2hermes WASM (uses wasi-sdk).
 *
 * Usage:
 *   bun run build              # build hbc.wasm
 *   bun run build -- --clean   # remove dist/
 *
 * Requires wasi-sdk. Run setup-wasi-sdk.ts to install, or set WASI_SDK_PATH.
 */

import { access, mkdir, readFile, rm, writeFile } from "fs/promises";
import { homedir } from "os";
import { resolve, join } from "path";

const ROOT = import.meta.dirname;
const R2HERMES = resolve(ROOT, "../r2hermes");
const DIST = join(ROOT, "dist");

if (process.argv.includes("--clean")) {
  await rm(DIST, { recursive: true, force: true });
  console.log("cleaned dist/");
  process.exit(0);
}

const exists = (p: string) =>
  access(p).then(
    () => true,
    () => false,
  );

async function findWasiSdk() {
  if (process.env.WASI_SDK_PATH) return process.env.WASI_SDK_PATH;
  for (const p of [
    "/opt/wasi-sdk",
    "/opt/homebrew/opt/wasi-sdk/share/wasi-sdk",
    join(homedir(), ".wasi-sdk"),
  ]) {
    if (await exists(join(p, "bin"))) return p;
  }
}

const WASI_SDK = await findWasiSdk();

// re-verify async
if (!WASI_SDK || !(await exists(join(WASI_SDK, "bin")))) {
  console.error(
    "wasi-sdk not found. Set WASI_SDK_PATH or run:\n" +
      "  bun run setup\n" +
      "  https://github.com/WebAssembly/wasi-sdk/releases",
  );
  process.exit(1);
}

const CC = join(
  WASI_SDK,
  "bin",
  process.platform === "win32" ? "clang.exe" : "clang",
);
const SYSROOT = join(WASI_SDK, "share", "wasi-sysroot");

const mesonBuild = await readFile(join(R2HERMES, "meson.build"), "utf8");
const versionMatch = mesonBuild.match(/version:\s*'([^']+)'/);
const version = versionMatch?.[1] ?? "0.0.0";
const [major, minor, patch] = version.split(".");

const versionDir = join(R2HERMES, "include", "hbc");
const versionH = join(versionDir, "version.h");
const versionContent =
  `#ifndef LIBHBC_VERSION\n` +
  `#define LIBHBC_VERSION "${version}"\n` +
  `#define LIBHBC_VERSION_MAJOR "${major}"\n` +
  `#define LIBHBC_VERSION_MINOR "${minor}"\n` +
  `#define LIBHBC_VERSION_PATCH "${patch}"\n` +
  `#endif\n`;

await mkdir(versionDir, { recursive: true });
const current = await readFile(versionH, "utf8").catch(() => "");
if (current !== versionContent) {
  await writeFile(versionH, versionContent);
  console.log(`generated version.h (${version})`);
}

const SRC = [
  "src/lib/utils/string_buffer.c",
  "src/lib/utils/buffer_reader.c",
  "src/lib/parsers/hbc_file_parser.c",
  "src/lib/parsers/hbc_bytecode_parser.c",
  "src/lib/opcodes/isa.c",
  "src/lib/opcodes/encoder.c",
  "src/lib/opcodes/decoder.c",
  "src/lib/decompilation/decompiler.c",
  "src/lib/decompilation/translator.c",
  "src/lib/decompilation/token.c",
  "src/lib/decompilation/literals.c",
  "src/lib/hbc.c",
].map((f) => join(R2HERMES, f));

const WRAPPER = join(ROOT, "hbc_wasm.c");
await mkdir(DIST, { recursive: true });

const OUTPUT = join(DIST, "hbc.wasm");

const flags = [
  "--target=wasm32-wasip1",
  `--sysroot=${SYSROOT}`,
  "-std=c11",
  "-O2",
  "-D_POSIX_C_SOURCE=200809L",
  `-I${join(R2HERMES, "include")}`,
  `-I${join(R2HERMES, "src/lib")}`,
  "-nostartfiles",
  "-Wl,--no-entry",
  "-Wl,--export=malloc",
  "-Wl,--export=free",
  "-Wl,--export=hbc_wasm_open",
  "-Wl,--export=hbc_wasm_info",
  "-Wl,--export=hbc_wasm_functions",
  "-Wl,--export=hbc_wasm_strings",
  "-Wl,--export=hbc_wasm_decompile",
  "-Wl,--export=hbc_wasm_decompile_all",
  "-Wl,--export=hbc_wasm_decompile_offsets",
  "-Wl,--export=hbc_wasm_decompile_offsets_all",
  "-Wl,--export=hbc_wasm_disassemble",
  "-Wl,--export=hbc_wasm_disassemble_all",
  "-Wl,--export=hbc_wasm_xrefs",
  "-Wl,--export=hbc_wasm_close",
  "-Wl,--export=hbc_wasm_free",
  "-Wl,-z,stack-size=65536",
  "-Wl,--strip-debug",
  "-o",
  OUTPUT,
];

console.log(`compiling with wasi-sdk → ${OUTPUT}`);
await Bun.$`${CC} ${SRC} ${WRAPPER} ${flags}`;

const { size } = Bun.file(OUTPUT);
console.log(`done: ${OUTPUT} (${(size / 1024).toFixed(0)} KB)`);
