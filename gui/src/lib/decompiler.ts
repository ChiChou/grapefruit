export type Target = "x86" | "x64" | "arm" | "thumb" | "arm64" | "arm64e";

export interface Input {
  data: ArrayBuffer;
  target: Target | "dex";
  address: string;
  base?: string;
  thumb?: boolean;
}

export function target(arch: string, bits: number): Target | null {
  if (arch === "arm64e") return "arm64e";
  if (arch === "arm64" || arch === "aarch64") return "arm64";
  if (arch === "thumb") return "thumb";
  if (arch === "arm") return bits === 64 ? "arm64" : bits === 16 ? "thumb" : bits === 32 ? "arm" : null;
  if (arch === "x64" || arch === "x86_64") return "x64";
  if (arch === "ia32") return "x86";
  if (arch === "x86") return bits === 64 ? "x64" : bits === 32 ? "x86" : null;
  return null;
}

export function decompile(input: Input, signal: AbortSignal): Promise<string> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL("./decompiler.worker.ts", import.meta.url), { type: "module" });
    const finish = (error?: Error, code?: string) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      worker.terminate();
      if (error) reject(error);
      else resolve(code ?? "");
    };
    const abort = () => finish(new DOMException("Decompilation cancelled", "AbortError"));
    const timer = setTimeout(() => finish(new Error("Decompilation exceeded 60 seconds")), 60_000);
    signal.addEventListener("abort", abort, { once: true });
    worker.onmessage = ({ data }: MessageEvent<{ code?: string; error?: string }>) =>
      finish(data.error ? new Error(data.error) : undefined, data.code);
    worker.onerror = (event) => finish(new Error(event.message || "Decompiler worker failed"));
    worker.postMessage(input);
  });
}

export async function snapshot(
  cmd: (command: string) => Promise<string>,
  address: string,
): Promise<Input> {
  if (!/^0x[\da-f]+$/i.test(address)) throw new Error("Invalid function address");
  const arch = (await cmd("e asm.arch")).trim();
  const bits = Number((await cmd("e asm.bits")).trim());
  let cpu = target(arch, bits);
  if (cpu === "arm64" && (await cmd("e asm.os")).trim() === "darwin") cpu = "arm64e";
  if (!cpu) throw new Error(`Kuna does not support ${arch}/${bits}`);
  const thumb = cpu === "thumb" || (cpu === "arm" && (BigInt(address) & 1n) === 1n);
  const entry = thumb ? `0x${(BigInt(address) & ~1n).toString(16)}` : address;
  const funcs = JSON.parse(await cmd(`afij @ ${entry}`)) as { offset?: number; addr?: number; size?: number; maxbound?: number; bits?: number }[];
  const fn = funcs[0];
  const start = fn?.offset ?? fn?.addr;
  const size = fn?.maxbound && start !== undefined ? fn.maxbound - start : fn?.size;
  if (start === undefined || !Number.isSafeInteger(start) || !size || !Number.isSafeInteger(size) || size < 1 || size > 1024 * 1024) {
    throw new Error("No bounded function snapshot available (maximum 1 MiB)");
  }
  const base = `0x${start.toString(16)}`;
  const hex = (await cmd(`p8 ${size} @ ${base}`)).trim();
  if (!/^[\da-f]+$/i.test(hex) || hex.length !== size * 2) throw new Error("Could not read the complete function snapshot");
  const data = Uint8Array.from(hex.match(/../g)!, (byte) => parseInt(byte, 16)).buffer;
  return { data, target: cpu, base, address: base, thumb: thumb || fn.bits === 16 };
}
