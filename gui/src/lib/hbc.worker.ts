import wasmUrl from "r2hermes-wasm/dist/hbc.wasm?url";

const decoder = new TextDecoder();

function utf8(memory: WebAssembly.Memory, ptr: number): string {
  const buf = new Uint8Array(memory.buffer, ptr);
  const end = buf.indexOf(0);
  return decoder.decode(buf.subarray(0, end === -1 ? undefined : end));
}

let inst: WebAssembly.Instance | null = null;
let loading: Promise<WebAssembly.Instance> | null = null;

function zeroOut(memory: WebAssembly.Memory, ...ptrs: number[]): number {
  const view = new DataView(memory.buffer);
  for (const p of ptrs) view.setUint32(p, 0, true);
  return 0;
}

function postStatus(status: string, progress?: number) {
  self.postMessage({ id: -1, ok: true, result: { status, progress } });
}

async function load(): Promise<WebAssembly.Instance> {
  if (inst) return inst;
  if (loading) return loading;
  loading = (async () => {
    postStatus("downloading");
    const res = await fetch(wasmUrl);
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
    const wasmBytes = new Uint8Array(received);
    let offset = 0;
    for (const chunk of chunks) { wasmBytes.set(chunk, offset); offset += chunk.byteLength; }
    postStatus("compiling");
    let mem: WebAssembly.Memory;
    const wasi: Record<string, Function> = {
      fd_write: (_fd: number, iovs: number, iovsLen: number, nwritten: number) => {
        // Sum iov lengths and report all bytes "written" to prevent stdio retry loops
        const view = new DataView(mem.buffer);
        let total = 0;
        for (let i = 0; i < iovsLen; i++) {
          total += view.getUint32(iovs + i * 8 + 4, true);
        }
        view.setUint32(nwritten, total, true);
        return 0;
      },
      fd_read: () => 0,
      fd_close: () => 0,
      fd_seek: () => 0,
      fd_fdstat_get: () => 0,
      fd_prestat_get: () => 8,
      fd_prestat_dir_name: () => 8,
      proc_exit: (code: number) => {
        throw new Error(`proc_exit(${code})`);
      },
      environ_get: () => 0,
      environ_sizes_get: (a: number, b: number) => zeroOut(mem, a, b),
      args_get: () => 0,
      args_sizes_get: (a: number, b: number) => zeroOut(mem, a, b),
      clock_time_get: () => 0,
    };
    const { instance: i } = await WebAssembly.instantiate(wasmBytes.buffer, {
      wasi_snapshot_preview1: wasi,
    });
    mem = i.exports.memory as WebAssembly.Memory;
    inst = i;
    postStatus("ready");
    return i;
  })();
  return loading;
}

interface Exports {
  memory: WebAssembly.Memory;
  malloc: (size: number) => number;
  free: (ptr: number) => void;
  hbc_wasm_open: (ptr: number, len: number) => number;
  hbc_wasm_close: (handle: number) => void;
  hbc_wasm_free: (ptr: number) => void;
  hbc_wasm_info: (handle: number) => number;
  hbc_wasm_functions: (handle: number) => number;
  hbc_wasm_strings: (handle: number) => number;
  hbc_wasm_decompile: (handle: number, funcId: number) => number;
  hbc_wasm_decompile_offsets: (handle: number, funcId: number) => number;
  hbc_wasm_decompile_all: (handle: number) => number;
  hbc_wasm_decompile_offsets_all: (handle: number) => number;
  hbc_wasm_disassemble: (handle: number, funcId: number) => number;
  hbc_wasm_disassemble_all: (handle: number) => number;
  hbc_wasm_xrefs: (handle: number) => number;
}

let ex: Exports | null = null;
let handle = -1;

function str(fn: (handle: number, ...args: number[]) => number, ...args: number[]): string | null {
  const ptr = fn(handle, ...args);
  if (!ptr) return null;
  const s = utf8(ex!.memory, ptr);
  ex!.hbc_wasm_free(ptr);
  return s;
}

type Request =
  | { id: number; type: "open"; buffer: ArrayBuffer }
  | { id: number; type: "close" }
  | { id: number; type: "disassemble"; funcId?: number }
  | { id: number; type: "decompile"; funcId?: number; offsets?: boolean }
  | { id: number; type: "info" }
  | { id: number; type: "functions" }
  | { id: number; type: "strings" }
  | { id: number; type: "xrefs" }
  | { id: number; type: "analyze" };

self.onmessage = async (e: MessageEvent<Request>) => {
  const msg = e.data;
  try {
    switch (msg.type) {
      case "open": {
        const i = await load();
        ex = i.exports as unknown as Exports;
        const bytes = new Uint8Array(msg.buffer);
        const ptr = ex.malloc(bytes.byteLength);
        if (!ptr) throw new Error("Failed to allocate WASM memory");
        new Uint8Array(ex.memory.buffer, ptr, bytes.byteLength).set(bytes);
        handle = ex.hbc_wasm_open(ptr, bytes.byteLength);
        ex.free(ptr);
        if (handle < 0) throw new Error("Failed to parse Hermes bytecode");
        self.postMessage({ id: msg.id, ok: true });
        break;
      }

      case "close": {
        if (handle >= 0 && ex) {
          ex.hbc_wasm_close(handle);
          handle = -1;
        }
        self.postMessage({ id: msg.id, ok: true });
        break;
      }

      case "analyze": {
        if (!ex || handle < 0) throw new Error("Not opened");
        const info = JSON.parse(str(ex.hbc_wasm_info)!);
        const functions = JSON.parse(str(ex.hbc_wasm_functions)!);
        const strings = JSON.parse(str(ex.hbc_wasm_strings)!);
        const xrefs = JSON.parse(str(ex.hbc_wasm_xrefs)!);
        self.postMessage({ id: msg.id, ok: true, result: { info, functions, strings, xrefs } });
        break;
      }

      case "disassemble": {
        if (!ex || handle < 0) throw new Error("Not opened");
        let result: string | null;
        if (msg.funcId != null) {
          result = str(ex.hbc_wasm_disassemble, msg.funcId);
        } else {
          result = str(ex.hbc_wasm_disassemble_all);
        }
        self.postMessage({ id: msg.id, ok: true, result });
        break;
      }

      case "decompile": {
        if (!ex || handle < 0) throw new Error("Not opened");
        let result: string | null;
        if (msg.funcId != null) {
          const fn = msg.offsets ? ex.hbc_wasm_decompile_offsets : ex.hbc_wasm_decompile;
          result = str(fn, msg.funcId);
        } else {
          const fn = msg.offsets ? ex.hbc_wasm_decompile_offsets_all : ex.hbc_wasm_decompile_all;
          result = str(fn);
        }
        self.postMessage({ id: msg.id, ok: true, result });
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
