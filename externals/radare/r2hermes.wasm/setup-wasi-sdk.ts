/**
 * Downloads and installs wasi-sdk for the current platform.
 * Installs to ~/.wasi-sdk by default, or WASI_SDK_PATH if set.
 *
 * Usage:
 *   bun externals/radare/r2hermes.wasm/setup-wasi-sdk.ts
 */

import { access, mkdir, unlink, writeFile } from "fs/promises";
import { homedir, tmpdir } from "os";
import { join, resolve } from "path";

const VERSION = 32;
const BASE = `https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${VERSION}`;

function platform(): string {
  const osMap: Record<string, string> = {
    linux: "linux",
    darwin: "macos",
    win32: "windows",
  };
  const archMap: Record<string, string> = {
    x64: "x86_64",
    arm64: "arm64",
  };
  if (!(process.platform in osMap) || !(process.arch in archMap))
    throw new Error(`unsupported: ${process.platform}-${process.arch}`);
  return `${osMap[process.platform]}-${archMap[process.arch]}`;
}

const plat = platform();
const archive = `wasi-sdk-${VERSION}.0-${plat}.tar.gz`;
const url = `${BASE}/${archive}`;
const dest = resolve(process.env.WASI_SDK_PATH ?? join(homedir(), ".wasi-sdk"));
const clang = process.platform === "win32" ? "clang.exe" : "clang";

if (
  await access(join(dest, "bin", clang)).then(
    () => true,
    () => false,
  )
) {
  console.log(`wasi-sdk already installed at ${dest}`);
  process.exit(0);
}

console.log(`downloading ${archive}...`);
const res = await fetch(url);
if (!res.ok)
  throw new Error(`download failed: ${res.status} ${res.statusText}`);

const tmp = join(tmpdir(), archive);
await writeFile(tmp, Buffer.from(await res.arrayBuffer()));

await mkdir(dest, { recursive: true });
await Bun.$`tar xzf ${tmp} -C ${dest} --strip-components=1`;
await unlink(tmp);

console.log(`installed wasi-sdk ${VERSION} to ${dest}`);
console.log(`export WASI_SDK_PATH=${dest}`);
