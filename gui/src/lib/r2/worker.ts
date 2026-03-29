/**
 * Web Worker that runs radare2 WASM with browser WASI shim.
 * Provides an RPC interface for R2 commands from the main thread.
 */
import {
  WASI,
  PreopenDirectory,
  File,
  OpenFile,
  ConsoleStdout,
} from "@bjorn3/browser_wasi_shim";
import * as cache from "./store";

const R2_VERSION = "6.1.2";

interface R2Exports {
  memory: WebAssembly.Memory;
  malloc: (size: number) => number;
  free: (ptr: number) => void;
  r_core_new: () => number;
  r_core_cmd_str: (core: number, cmd: number) => number;
  r_core_file_open: (core: number, uri: number, mode: number, addr: bigint) => number;
  r_core_task_sync_begin: (core: number) => void;
  r_core_free: (core: number) => void;
}

let wasi: WASI;
let workDir: PreopenDirectory;
let ex: R2Exports;
let corePtr = 0;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function allocStr(s: string): number {
  const bytes = encoder.encode(s + "\0");
  const ptr = ex.malloc(bytes.length);
  new Uint8Array(ex.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

function readStr(ptr: number): string {
  if (!ptr) return "";
  const buf = new Uint8Array(ex.memory.buffer);
  let end = ptr;
  while (buf[end] !== 0) end++;
  return decoder.decode(buf.subarray(ptr, end));
}

function rawCmd(command: string): string {
  const cmdPtr = allocStr(command);
  const resPtr = ex.r_core_cmd_str(corePtr, cmdPtr);
  ex.free(cmdPtr);
  const result = readStr(resPtr);
  if (resPtr) ex.free(resPtr);
  return result;
}

function postStatus(status: string, progress?: number) {
  self.postMessage({ id: -1, ok: true, result: { status, progress } });
}

async function loadWasm(): Promise<ArrayBuffer> {
  // Check IndexedDB cache
  const cached = await cache.get(R2_VERSION);
  if (cached) {
    postStatus("cached");
    return cached;
  }

  // Download with progress
  postStatus("downloading");
  const res = await fetch("/radare2.wasm");
  const total = Number(res.headers.get("content-length") || 0);
  let received = 0;
  const chunks: Uint8Array[] = [];
  const reader = res.body!.getReader();
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.byteLength;
    if (total > 0) postStatus("downloading", Math.round((received / total) * 100));
  }

  const data = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }

  // Cache in IndexedDB
  await cache.put(R2_VERSION, data.buffer as ArrayBuffer);
  return data.buffer as ArrayBuffer;
}

type Request =
  | { id: number; type: "init"; arch?: string; bits?: number; os?: string }
  | { id: number; type: "loadFile"; name: string; data: ArrayBuffer }
  | { id: number; type: "cmd"; command: string }
  | { id: number; type: "writeMemory"; address: string; data: ArrayBuffer }
  | { id: number; type: "close" };

self.onmessage = async (e: MessageEvent<Request>) => {
  const msg = e.data;
  try {
    switch (msg.type) {
      case "init": {
        // Set up in-memory filesystem
        workDir = new PreopenDirectory("/work", new Map());

        const stdin = new OpenFile(new File([]));
        const stdout = ConsoleStdout.lineBuffered(() => {});
        const stderr = ConsoleStdout.lineBuffered(() => {});

        wasi = new WASI(
          ["radare2"],
          [],
          [stdin, stdout, stderr, workDir],
        );

        // Load WASM
        const wasmBytes = await loadWasm();
        postStatus("compiling");

        const module = await WebAssembly.compile(wasmBytes);

        // Add missing sock_accept if not in shim
        const imports = wasi.wasiImport as Record<string, Function>;
        if (!imports.sock_accept) imports.sock_accept = () => -1;

        const instance = await WebAssembly.instantiate(module, {
          wasi_snapshot_preview1: imports,
        });

        wasi.initialize(instance as any);
        ex = instance.exports as unknown as R2Exports;

        // Initialize R2 core
        corePtr = ex.r_core_new();
        if (!corePtr) throw new Error("r_core_new() failed");

        // Configure architecture
        if (msg.arch) rawCmd(`e asm.arch=${msg.arch}`);
        if (msg.bits) rawCmd(`e asm.bits=${msg.bits}`);
        if (msg.os) rawCmd(`e asm.os=${msg.os}`);
        rawCmd("e io.cache=1");
        rawCmd("e scr.color=0");

        // Open virtual address space
        const uriPtr = allocStr("malloc://268435456");
        ex.r_core_file_open(corePtr, uriPtr, 7, 0n);
        ex.free(uriPtr);
        ex.r_core_task_sync_begin(corePtr);

        postStatus("ready");
        self.postMessage({ id: msg.id, ok: true });
        break;
      }

      case "loadFile": {
        if (!ex || !corePtr) throw new Error("Not initialized");

        // Write file to in-memory VFS
        const fileData = new Uint8Array(msg.data);
        workDir.dir.contents.set(msg.name, new File(fileData));

        // Open in R2
        rawCmd("o--");
        rawCmd(`o /work/${msg.name}`);
        rawCmd("e scr.color=0");
        rawCmd("aaa");

        self.postMessage({ id: msg.id, ok: true });
        break;
      }

      case "cmd": {
        if (!ex || !corePtr) throw new Error("Not initialized");
        const result = rawCmd(msg.command);
        self.postMessage({ id: msg.id, ok: true, result });
        break;
      }

      case "writeMemory": {
        if (!ex || !corePtr) throw new Error("Not initialized");
        const bytes = new Uint8Array(msg.data);
        const addr = BigInt(msg.address);

        // Ensure mapping exists
        const addrHex = `0x${addr.toString(16)}`;
        const size = bytes.length;
        rawCmd(`o+ malloc://${size} ${addrHex} rwx`);

        // Write in 4KB chunks
        const hex = Array.from(bytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        const chunkSize = 4096;
        for (let off = 0; off < bytes.length; off += chunkSize) {
          const slice = hex.slice(off * 2, (off + chunkSize) * 2);
          const a = addr + BigInt(off);
          rawCmd(`wx ${slice} @ 0x${a.toString(16)}`);
        }

        self.postMessage({ id: msg.id, ok: true });
        break;
      }

      case "close": {
        if (corePtr && ex) {
          ex.r_core_free(corePtr);
          corePtr = 0;
        }
        self.postMessage({ id: msg.id, ok: true });
        break;
      }

      default:
        throw new Error(`Unknown message type: ${(msg as any).type}`);
    }
  } catch (e) {
    self.postMessage({
      id: msg.id,
      ok: false,
      error: e instanceof Error ? e.message : String(e),
    });
  }
};
