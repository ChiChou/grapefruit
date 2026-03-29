/**
 * JavaScript wrapper for the r2hermes WASI WASM module.
 * Direct WebAssembly instantiation with minimal WASI shim.
 */

const decoder = new TextDecoder();

function utf8(memory, ptr) {
  const buf = new Uint8Array(memory.buffer, ptr);
  const end = buf.indexOf(0);
  return decoder.decode(buf.subarray(0, end === -1 ? undefined : end));
}

let inst = null;
let loading = null;

function zeroOut(memory, ...ptrs) {
  const view = new DataView(memory.buffer);
  for (const p of ptrs) view.setUint32(p, 0, true);
  return 0;
}

async function load() {
  if (inst) return inst;
  if (loading) return loading;
  loading = (async () => {
    const wasmUrl = new URL("./dist/hbc.wasm", import.meta.url);
    let wasmBytes;
    if (typeof globalThis.Bun !== "undefined" || typeof process !== "undefined") {
      const { readFile } = await import("fs/promises");
      const { fileURLToPath } = await import("url");
      wasmBytes = await readFile(fileURLToPath(wasmUrl));
    } else {
      wasmBytes = await fetch(wasmUrl).then((r) => r.arrayBuffer());
    }
    /** @type {WebAssembly.Memory} */
    let mem;
    const wasi = {
      fd_write: () => 0,
      fd_read: () => 0,
      fd_close: () => 0,
      fd_seek: () => 0,
      fd_fdstat_get: () => 0,
      fd_prestat_get: () => 8,
      fd_prestat_dir_name: () => 8,
      proc_exit: (code) => { throw new Error(`proc_exit(${code})`); },
      environ_get: () => 0,
      environ_sizes_get: (a, b) => zeroOut(mem, a, b),
      args_get: () => 0,
      args_sizes_get: (a, b) => zeroOut(mem, a, b),
      clock_time_get: () => 0,
    };
    const { instance: i } = await WebAssembly.instantiate(wasmBytes, {
      wasi_snapshot_preview1: wasi,
    });
    mem = i.exports.memory;
    inst = i;
    return i;
  })();
  return loading;
}

export class HBC {
  #handle;
  #exports;

  constructor(handle, exports) {
    this.#handle = handle;
    this.#exports = exports;
  }

  static async fromBuffer(buffer) {
    const i = await load();
    const ex = i.exports;
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;

    const ptr = ex.malloc(bytes.byteLength);
    if (!ptr) throw new Error("Failed to allocate WASM memory");
    new Uint8Array(ex.memory.buffer, ptr, bytes.byteLength).set(bytes);

    const handle = ex.hbc_wasm_open(ptr, bytes.byteLength);
    ex.free(ptr);

    if (handle < 0) throw new Error("Failed to parse Hermes bytecode");
    return new HBC(handle, ex);
  }

  #str(fn, ...args) {
    const ptr = fn(this.#handle, ...args);
    if (!ptr) return null;
    const s = utf8(this.#exports.memory, ptr);
    this.#exports.hbc_wasm_free(ptr);
    return s;
  }

  info() {
    return JSON.parse(this.#str(this.#exports.hbc_wasm_info));
  }

  functions() {
    return JSON.parse(this.#str(this.#exports.hbc_wasm_functions));
  }

  strings() {
    return JSON.parse(this.#str(this.#exports.hbc_wasm_strings));
  }

  decompile(functionId, { offsets = false } = {}) {
    if (functionId != null) {
      const fn = offsets
        ? this.#exports.hbc_wasm_decompile_offsets
        : this.#exports.hbc_wasm_decompile;
      return this.#str(fn, functionId);
    }
    const fn = offsets
      ? this.#exports.hbc_wasm_decompile_offsets_all
      : this.#exports.hbc_wasm_decompile_all;
    return this.#str(fn);
  }

  disassemble(functionId) {
    if (functionId != null) {
      return this.#str(this.#exports.hbc_wasm_disassemble, functionId);
    }
    return this.#str(this.#exports.hbc_wasm_disassemble_all);
  }

  xrefs() {
    return JSON.parse(this.#str(this.#exports.hbc_wasm_xrefs));
  }

  close() {
    if (this.#handle >= 0) {
      this.#exports.hbc_wasm_close(this.#handle);
      this.#handle = -1;
    }
  }
}
