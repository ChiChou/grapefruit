import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  ConsoleStdout,
  File,
  OpenFile,
  PreopenDirectory,
  WASI,
} from "@bjorn3/browser_wasi_shim";

interface R2Exports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  malloc(size: number): number;
  free(ptr: number): void;
  r_core_new(): number;
  r_core_cmd_str(core: number, cmd: number): number;
  r_core_free(core: number): void;
}

const root = join(import.meta.dirname, "..", "..");
const wasm = process.argv[2] ?? join(root, "radare2.wasm");
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const dir = new PreopenDirectory("/work", new Map());
const stdin = new OpenFile(new File([]));
const stdout = ConsoleStdout.lineBuffered(() => {});
const stderr = ConsoleStdout.lineBuffered(() => {});
const wasi = new WASI(["radare2"], [], [stdin, stdout, stderr, dir]);
const module = await WebAssembly.compile(await readFile(wasm));
const imports = wasi.wasiImport as Record<string, WebAssembly.ImportValue>;
imports.sock_accept ??= (() => -1) as WebAssembly.ImportValue;
const instance = await WebAssembly.instantiate(module, {
  wasi_snapshot_preview1: imports,
});
wasi.initialize(instance as never);

const ex = instance.exports as R2Exports;
const core = ex.r_core_new();
if (!core) throw new Error("r_core_new() failed");

function alloc(value: string) {
  const bytes = encoder.encode(value + "\0");
  const ptr = ex.malloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function read(ptr: number) {
  const bytes = new Uint8Array(ex.memory.buffer);
  let end = ptr;
  while (bytes[end]) end++;
  return decoder.decode(bytes.subarray(ptr, end));
}

function cmd(value: string) {
  const input = alloc(value);
  const output = ex.r_core_cmd_str(core, input);
  ex.free(input);
  const result = output ? read(output) : "";
  if (output) ex.free(output);
  return result;
}

try {
  const flutter = cmd("r2flutter -V");
  if (!flutter.includes("r2flutter")) {
    throw new Error(`r2flutter command unavailable: ${JSON.stringify(flutter)}`);
  }

  const hermes = cmd("r2hermes-?");
  if (!hermes.includes("r2hermes")) {
    throw new Error(`r2hermes command unavailable: ${JSON.stringify(hermes)}`);
  }
  console.log(`[r2-wasm] plugins ready: ${flutter.trim()}, r2hermes`);

  const fixture = process.argv[3];
  if (fixture) {
    dir.dir.contents.set("fixture", new File(new Uint8Array(await readFile(fixture))));
    cmd("o /work/fixture");
    for (const action of ["H", "f", "c", "z", "x", "S"]) {
      const value = cmd(`r2flutter -q -j${action}`);
      JSON.parse(value);
      console.log(`[r2-wasm] r2flutter -j${action}: ${value.slice(0, 200)}`);
    }
  }
} finally {
  ex.r_core_free(core);
}
