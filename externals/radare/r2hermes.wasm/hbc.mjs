import createHBCModule from "./dist/hbc.mjs";

let modulePromise = null;

function getModule() {
  if (!modulePromise) {
    modulePromise = createHBCModule();
  }
  return modulePromise;
}

export class HBC {
  #handle;
  #module;

  constructor(handle, module) {
    this.#handle = handle;
    this.#module = module;
  }

  static async fromBuffer(buffer) {
    const mod = await getModule();
    const bytes = buffer instanceof ArrayBuffer ? new Uint8Array(buffer) : buffer;

    const ptr = mod._malloc(bytes.byteLength);
    if (!ptr) throw new Error("Failed to allocate WASM memory");
    mod.HEAPU8.set(bytes, ptr);

    const handle = mod._hbc_wasm_open(ptr, bytes.byteLength);
    mod._free(ptr);

    if (handle < 0) {
      throw new Error("Failed to parse Hermes bytecode");
    }

    return new HBC(handle, mod);
  }

  #callString(fn, ...args) {
    if (!fn) return null;
    const ptr = fn(this.#handle, ...args);
    if (!ptr) return null;
    const str = this.#module.UTF8ToString(ptr);
    this.#module._hbc_wasm_free(ptr);
    return str;
  }

  info() {
    return JSON.parse(this.#callString(this.#module._hbc_wasm_info));
  }

  functions() {
    return JSON.parse(this.#callString(this.#module._hbc_wasm_functions));
  }

  strings() {
    return JSON.parse(this.#callString(this.#module._hbc_wasm_strings));
  }

  decompile(functionId, { offsets = false } = {}) {
    if (functionId != null) {
      const fn = offsets && this.#module._hbc_wasm_decompile_offsets
        ? this.#module._hbc_wasm_decompile_offsets
        : this.#module._hbc_wasm_decompile;
      return this.#callString(fn, functionId);
    }
    const fn = offsets && this.#module._hbc_wasm_decompile_offsets_all
      ? this.#module._hbc_wasm_decompile_offsets_all
      : this.#module._hbc_wasm_decompile_all;
    return this.#callString(fn);
  }

  disassemble(functionId) {
    const fn = functionId != null
      ? this.#module._hbc_wasm_disassemble
      : this.#module._hbc_wasm_disassemble_all;
    if (!fn) return "; disassembly requires WASM rebuild (make -C externals/radare/r2hermes.wasm)";
    return (functionId != null
      ? this.#callString(fn, functionId)
      : this.#callString(fn)
    ) ?? "; disassembly failed";
  }

  close() {
    if (this.#handle >= 0) {
      this.#module._hbc_wasm_close(this.#handle);
      this.#handle = -1;
    }
  }
}
