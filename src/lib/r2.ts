import { WASI } from "node:wasi";
import { readFile, writeFile, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";

import frida from "./xvii.ts";
import { asset, agent } from "./assets.ts";
import { create as createTransport } from "./transport.ts";

export type ReadRequestHandler = (
  address: bigint,
  size: number,
) => Promise<Uint8Array | null>;

export interface FunctionBlock {
  addr: number;
  size: number;
  jump?: number;
  fail?: number;
  inputs?: number;
  outputs?: number;
  ninstr?: number;
  traced?: number;
}

export interface DisasmInstruction {
  offset: number;
  size: number;
  opcode: string;
  disasm: string;
  bytes: string;
  type: string;
  jump?: number;
  fail?: number;
  esil?: string;
  refs?: Array<{ addr: number; type: string }>;
  xrefs?: Array<{ addr: number; type: string }>;
}

export interface CfgFunction {
  name: string;
  addr: number;
  size: number;
  ninstr: number;
  nargs: number;
  nlocals: number;
  stack: number;
  type: string;
  blocks: CfgBlock[];
}

export interface CfgBlock {
  addr: number;
  size: number;
  jump?: number;
  fail?: number;
  ops: DisasmInstruction[];
}

interface R2WasiConfig {
  wasmBytes: Uint8Array;
  arch?: string;
  bits?: number;
  os?: string;
  onReadRequest: ReadRequestHandler;
  addressSpaceSize?: number;
  pageSize?: number;
}

class R2Wasi {
  #config: R2WasiConfig;
  #wasm!: WebAssembly.Instance;
  #memory!: WebAssembly.Memory;
  #exports!: Record<string, Function>;
  #pageCache = new Map<bigint, Uint8Array | null>();
  #started = false;
  #corePtr = 0;
  #tmpDir: string | null = null;

  constructor(config: R2WasiConfig) {
    this.#config = config;
  }

  get started(): boolean {
    return this.#started;
  }

  async start(): Promise<void> {
    this.#tmpDir = await mkdtemp(join(process.cwd(), ".r2-"));

    const wasi = new WASI({
      version: "preview1" as any,
      args: ["radare2"],
      env: {},
      // Bun's WASI ignores the preopens target and maps to CWD,
      // so we point /work at CWD and place temp files under it
      preopens: { "/work": process.cwd() },
    });

    const module = await WebAssembly.compile(this.#config.wasmBytes.buffer as ArrayBuffer);

    // Bun's WASI uses getImports(module) instead of Node's getImportObject()
    let importObject: WebAssembly.Imports;
    if (typeof (wasi as any).getImportObject === "function") {
      importObject = (wasi as any).getImportObject();
    } else {
      importObject = (wasi as any).getImports(module);
    }

    // Stub missing WASI functions (e.g. sock_accept not in Bun)
    const wasiNs = importObject.wasi_snapshot_preview1 as Record<string, unknown>;
    if (wasiNs && !wasiNs.sock_accept) {
      wasiNs.sock_accept = () => -1;
    }

    this.#wasm = await WebAssembly.instantiate(module, importObject);
    this.#exports = this.#wasm.exports as any;
    this.#memory = this.#exports.memory as unknown as WebAssembly.Memory;

    // Initialize WASI (reactor or command style)
    if (typeof (wasi as any).initialize === "function") {
      (wasi as any).initialize(this.#wasm);
    } else if (typeof (wasi as any).start === "function") {
      (wasi as any).start(this.#wasm);
    }

    const core = this.#exports.r_core_new() as number;
    if (!core) throw new Error("r_core_new() failed");
    this.#corePtr = core;

    const { arch, bits, os } = this.#config;
    if (arch) this.#rawCmd(`e asm.arch=${arch}`);
    if (bits) this.#rawCmd(`e asm.bits=${bits}`);
    if (os) this.#rawCmd(`e asm.os=${os}`);

    this.#rawCmd("e io.cache=1");
    this.#rawCmd("e scr.color=0");

    const addrSpace = this.#config.addressSpaceSize ?? 0x10000000;
    const uriPtr = this.#allocString(`malloc://${addrSpace}`);
    this.#exports.r_core_file_open(core, uriPtr, 7, 0n);
    this.#exports.free(uriPtr);
    this.#exports.r_core_task_sync_begin(this.#corePtr);

    this.#started = true;
  }

  #allocString(s: string): number {
    const encoded = new TextEncoder().encode(s + "\0");
    const ptr = this.#exports.malloc(encoded.length) as number;
    new Uint8Array(this.#memory.buffer, ptr, encoded.length).set(encoded);
    return ptr;
  }

  #readString(ptr: number): string {
    if (!ptr) return "";
    const buf = new Uint8Array(this.#memory.buffer);
    let end = ptr;
    while (buf[end] !== 0) end++;
    return new TextDecoder().decode(buf.subarray(ptr, end));
  }

  #rawCmd(command: string): string {
    const cmdPtr = this.#allocString(command);
    const resultPtr = this.#exports.r_core_cmd_str(this.#corePtr, cmdPtr) as number;
    this.#exports.free(cmdPtr);
    const result = this.#readString(resultPtr);
    if (resultPtr) this.#exports.free(resultPtr);
    return result;
  }

  rawCmd(command: string): string {
    if (!this.#started) throw new Error("R2Wasi not started");
    return this.#rawCmd(command);
  }

  async cmd(command: string): Promise<string> {
    // Prefetch memory for @ 0x... or s 0x... (seek) patterns
    const addrMatch = command.match(/(?:@|^s)\s*(0x[0-9a-fA-F]+)/);
    if (addrMatch) {
      const addr = BigInt(addrMatch[1]);
      await this.mapMemory(addr, this.#config.pageSize ?? 4096);
    }
    return this.#rawCmd(command);
  }

  async cmdj<T = unknown>(command: string): Promise<T> {
    const jsonCmd = command.endsWith("j") ? command : command + "j";
    const result = await this.cmd(jsonCmd);
    return JSON.parse(result);
  }

  writeBytes(address: bigint, data: Uint8Array): void {
    const pageSize = BigInt(this.#config.pageSize ?? 4096);
    const mapStart = address - (address % pageSize);
    const mapEnd = address + BigInt(data.length);
    const mapEndAligned =
      mapEnd % pageSize === 0n ? mapEnd : mapEnd + pageSize - (mapEnd % pageSize);
    const mapSize = Number(mapEndAligned - mapStart);
    const mapStartHex = `0x${mapStart.toString(16)}`;

    if (!this.#hasMappingAt(mapStart, mapSize)) {
      this.#rawCmd(`o+ malloc://${mapSize} ${mapStartHex} rwx`);
    }

    const chunkSize = 4096;
    const hex = Array.from(data)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    for (let off = 0; off < data.length; off += chunkSize) {
      const slice = hex.slice(off * 2, (off + chunkSize) * 2);
      const addr = address + BigInt(off);
      this.#rawCmd(`wx ${slice} @ 0x${addr.toString(16)}`);
    }
  }

  #hasMappingAt(address: bigint, size: number): boolean {
    const raw = this.#rawCmd("omj");
    try {
      const maps: Array<{ from: number; to: number }> = JSON.parse(raw);
      const start = Number(address);
      const end = start + size;
      return maps.some((m) => m.from <= start && m.to >= end);
    } catch {
      return false;
    }
  }

  async mapMemory(address: bigint, size: number): Promise<boolean> {
    const pageSize = BigInt(this.#config.pageSize ?? 4096);
    const startPage = address - (address % pageSize);
    const endAddr = address + BigInt(size);
    const endPage =
      endAddr % pageSize === 0n ? endAddr : endAddr + pageSize - (endAddr % pageSize);

    let fetchStart: bigint | null = null;
    let fetchEnd = startPage;
    const fetches: Array<{ start: bigint; size: number }> = [];

    for (let p = startPage; p < endPage; p += pageSize) {
      const cached = this.#pageCache.get(p);
      if (cached === null) return false;
      if (cached === undefined) {
        if (fetchStart === null) fetchStart = p;
        fetchEnd = p + pageSize;
      } else if (fetchStart !== null) {
        fetches.push({ start: fetchStart, size: Number(fetchEnd - fetchStart) });
        fetchStart = null;
      }
    }
    if (fetchStart !== null) {
      fetches.push({ start: fetchStart, size: Number(fetchEnd - fetchStart) });
    }

    if (fetches.length === 0) return true;

    for (const { start, size } of fetches) {
      const data = await this.#config.onReadRequest(start, size);
      if (!data) {
        for (let p = start; p < start + BigInt(size); p += pageSize) {
          this.#pageCache.set(p, null);
        }
        return false;
      }
      this.writeBytes(start, data);
      for (let p = start; p < start + BigInt(size); p += pageSize) {
        this.#pageCache.set(p, new Uint8Array(0));
      }
    }
    return true;
  }

  async analyzeFunction(
    address: bigint,
    opts: { maxRounds?: number; mapAhead?: number } = {},
  ): Promise<FunctionBlock[] | null> {
    const pageSize = this.#config.pageSize ?? 4096;
    const maxRounds = opts.maxRounds ?? 10;
    const mapAhead = opts.mapAhead ?? pageSize * 4;
    const addrHex = `0x${address.toString(16)}`;

    if (!(await this.mapMemory(address, mapAhead))) return null;

    for (let round = 0; round < maxRounds; round++) {
      this.#rawCmd(`af- @ ${addrHex}`);
      this.#rawCmd(`af @ ${addrHex}`);

      const blocksJson = this.#rawCmd(`afbj @ ${addrHex}`);
      let blocks: FunctionBlock[];
      try {
        blocks = JSON.parse(blocksJson);
      } catch {
        return null;
      }
      if (!blocks || blocks.length === 0) return null;

      const targets = new Set<bigint>();
      for (const b of blocks) {
        targets.add(BigInt(b.addr) + BigInt(b.size));
        if (b.jump != null && b.jump !== -1) targets.add(BigInt(b.jump));
        if (b.fail != null && b.fail !== -1) targets.add(BigInt(b.fail));
      }

      let mapped = 0;
      for (const t of targets) {
        const tPage = t - (t % BigInt(pageSize));
        if (!this.#pageCache.has(tPage)) {
          if (await this.mapMemory(t, mapAhead)) mapped++;
        }
      }

      if (mapped === 0) return blocks;
    }

    const final = this.#rawCmd(`afbj @ ${addrHex}`);
    try {
      return JSON.parse(final);
    } catch {
      return null;
    }
  }

  async disassembleFunction(address: bigint): Promise<string | null> {
    const blocks = await this.analyzeFunction(address);
    if (!blocks) return null;
    return this.#rawCmd(`pdf @ 0x${address.toString(16)}`);
  }

  async disassembleFunctionJson(address: bigint): Promise<any | null> {
    const blocks = await this.analyzeFunction(address);
    if (!blocks) return null;
    const raw = this.#rawCmd(`pdfj @ 0x${address.toString(16)}`);
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  async functionGraph(address: bigint): Promise<CfgFunction | null> {
    const blocks = await this.analyzeFunction(address);
    if (!blocks) return null;
    const raw = this.#rawCmd(`agfj @ 0x${address.toString(16)}`);
    try {
      const arr: CfgFunction[] = JSON.parse(raw);
      return arr?.[0] ?? null;
    } catch {
      return null;
    }
  }

  async loadFile(data: Uint8Array, filename?: string): Promise<void> {
    const name = filename ?? "input.bin";
    await writeFile(join(this.#tmpDir!, name), data);
    // Bun's WASI maps /work → CWD, so use the relative path from CWD
    const relPath = join(this.#tmpDir!, name).replace(process.cwd() + "/", "");
    this.#rawCmd("o--");
    this.#rawCmd(`o /work/${relPath}`);
    this.#rawCmd("e scr.color=0");
  }

  close(): void {
    if (this.#corePtr) {
      this.#exports.r_core_free(this.#corePtr);
      this.#corePtr = 0;
    }
    this.#started = false;
    if (this.#tmpDir) {
      rm(this.#tmpDir, { recursive: true, force: true }).catch(() => {});
      this.#tmpDir = null;
    }
  }
}

export interface R2Session {
  id: string;
  r2: R2Wasi;
  fridaCleanup?: () => Promise<void>;
  createdAt: number;
  lastUsed: number;
}

const sessions = new Map<string, R2Session>();

let wasmBytes: Uint8Array | null = null;

async function getWasmBytes(): Promise<Uint8Array> {
  if (wasmBytes) return wasmBytes;
  const wasmPath = await asset("radare2.wasm");
  wasmBytes = new Uint8Array(await readFile(wasmPath));
  return wasmBytes;
}

function archFromFrida(arch: string): string {
  switch (arch) {
    case "ia32":
    case "x64":
      return "x86";
    case "arm64":
      return "arm";
    default:
      return arch;
  }
}

function bitsFromFrida(arch: string, pointerSize: number): number {
  if (pointerSize) return pointerSize * 8;
  switch (arch) {
    case "x64":
    case "arm64":
      return 64;
    default:
      return 32;
  }
}

export async function createLiveSession(opts: {
  deviceId: string;
  pid: number;
  arch: string;
  platform: string;
  pointerSize: number;
  pageSize: number;
}): Promise<R2Session> {
  const device = await frida.getDevice(opts.deviceId);
  const fridaSession = await device.attach(opts.pid);
  const fridaScript = await fridaSession.createScript(`
    rpc.exports = {
      readMemory(address, size) {
        try { return ptr(address).readByteArray(size); }
        catch(e) { return null; }
      }
    };
  `);
  await fridaScript.load();

  const id = randomUUID();
  const r2 = new R2Wasi({
    wasmBytes: await getWasmBytes(),
    arch: archFromFrida(opts.arch),
    bits: bitsFromFrida(opts.arch, opts.pointerSize),
    os: opts.platform,
    pageSize: opts.pageSize,
    async onReadRequest(address, size) {
      try {
        const buf = await fridaScript.exports.readMemory(
          "0x" + address.toString(16),
          size,
        );
        if (!buf) return null;
        if (buf instanceof ArrayBuffer) return new Uint8Array(buf);
        if (buf instanceof Buffer) return new Uint8Array(buf);
        if ((buf as any).buffer) return new Uint8Array((buf as any).buffer);
        return new Uint8Array(buf as ArrayBuffer);
      } catch {
        return null;
      }
    },
  });

  await r2.start();

  const cc =
    opts.arch === "arm64" ? "aapcs64" : opts.arch === "arm" ? "aapcs" : "cdecl";
  r2.rawCmd(`e anal.cc=${cc}`);
  r2.rawCmd("e anal.depth=64");
  r2.rawCmd("e anal.hasnext=true");

  const session: R2Session = {
    id,
    r2,
    async fridaCleanup() {
      await fridaScript.unload();
      await fridaSession.detach();
    },
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };
  sessions.set(id, session);
  return session;
}

export async function createFileSession(
  data: Uint8Array,
  filename: string,
): Promise<R2Session> {
  const id = randomUUID();
  const r2 = new R2Wasi({
    wasmBytes: await getWasmBytes(),
    async onReadRequest() {
      return null;
    },
  });

  await r2.start();
  await r2.loadFile(data, filename);

  const session: R2Session = {
    id,
    r2,
    createdAt: Date.now(),
    lastUsed: Date.now(),
  };
  sessions.set(id, session);
  return session;
}

async function pullFileToBuffer(
  device: import("./xvii.ts").Device,
  pid: number,
  path: string,
): Promise<Uint8Array> {
  const transport = await createTransport(device, pid);
  const { script, controller } = transport;

  const size: number = await script.exports.len(path);
  const chunks: Uint8Array[] = [];

  await new Promise<void>((resolve, reject) => {
    controller.events.on("stream", async (incoming: import("node:stream").Readable) => {
      for await (const chunk of incoming) {
        chunks.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
      }
      await transport.close();
      resolve();
    });
    script.exports.pull(path).catch(reject);
  });

  const result = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    result.set(c, off);
    off += c.length;
  }
  return result;
}

async function pullZipEntryToBuffer(
  device: import("./xvii.ts").Device,
  pid: number,
  apkPath: string,
  entry: string,
): Promise<Uint8Array> {
  const transport = await createTransport(device, pid);
  const { script, controller } = transport;

  const size: number = await script.exports.zipLen(apkPath, entry);
  const chunks: Uint8Array[] = [];

  await new Promise<void>((resolve, reject) => {
    controller.events.on("stream", async (incoming: import("node:stream").Readable) => {
      for await (const chunk of incoming) {
        chunks.push(chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk));
      }
      await transport.close();
      resolve();
    });
    script.exports.pullZip(apkPath, entry).catch(reject);
  });

  const result = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    result.set(c, off);
    off += c.length;
  }
  return result;
}

export async function createDeviceFileSession(opts: {
  deviceId: string;
  pid: number;
  path?: string;
  apk?: string;
  entry?: string;
}): Promise<R2Session> {
  const device = await frida.getDevice(opts.deviceId);

  let data: Uint8Array;
  let filename: string;

  if (opts.apk && opts.entry) {
    data = await pullZipEntryToBuffer(device, opts.pid, opts.apk, opts.entry);
    filename = opts.entry.split("/").pop() ?? "entry.bin";
  } else if (opts.path) {
    data = await pullFileToBuffer(device, opts.pid, opts.path);
    filename = opts.path.split("/").pop() ?? "file.bin";
  } else {
    throw new Error("path or apk+entry required");
  }

  return createFileSession(data, filename);
}

export function getSession(id: string): R2Session | undefined {
  const s = sessions.get(id);
  if (s) s.lastUsed = Date.now();
  return s;
}

export async function closeSession(id: string): Promise<boolean> {
  const s = sessions.get(id);
  if (!s) return false;
  s.r2.close();
  if (s.fridaCleanup) await s.fridaCleanup();
  sessions.delete(id);
  return true;
}

export function listSessions(): Array<{
  id: string;
  createdAt: number;
  lastUsed: number;
}> {
  return [...sessions.values()].map((s) => ({
    id: s.id,
    createdAt: s.createdAt,
    lastUsed: s.lastUsed,
  }));
}

const SESSION_TTL = 30 * 60 * 1000; // 30 minutes

setInterval(() => {
  const now = Date.now();
  for (const [id, s] of sessions) {
    if (now - s.lastUsed > SESSION_TTL) {
      console.info(`[r2] closing idle session ${id}`);
      s.r2.close();
      s.fridaCleanup?.();
      sessions.delete(id);
    }
  }
}, 60 * 1000);
