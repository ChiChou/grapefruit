import { WASI, File, OpenFile, Directory, PreopenDirectory, ConsoleStdout, type Inode } from "@bjorn3/browser_wasi_shim";
import type { Input } from "../decompiler";

export async function run(module: WebAssembly.Module, bundle: Record<string, string>, input: Input): Promise<string> {
  const tree = new Map<string, Inode>();
  for (const [path, value] of Object.entries(bundle)) {
    const parts = path.split("/");
    let dir = tree;
    for (const part of parts.slice(0, -1)) {
      if (!dir.has(part)) dir.set(part, new Directory(new Map()));
      dir = (dir.get(part) as Directory).contents;
    }
    dir.set(parts.at(-1)!, new File(Uint8Array.from(atob(value), (c) => c.charCodeAt(0))));
  }
  const stdout: string[] = [];
  const stderr: string[] = [];
  const isa = input.thumb || input.target === "thumb" ? "thumb" : input.base && input.target === "arm" ? "arm" : "auto";
  const args = input.target === "dex" ? ["igf-ddc", input.address] : [
    "igf-kuna", input.base ? "raw" : "file", input.target,
    input.base ?? "0x0", input.address, isa,
  ];
  const wasi = new WASI(args, [], [
    new OpenFile(new File([])),
    ConsoleStdout.lineBuffered((line) => stdout.push(line)),
    ConsoleStdout.lineBuffered((line) => stderr.push(line)),
    new PreopenDirectory("/specs", tree),
    new PreopenDirectory("/work", new Map([["input", new File(new Uint8Array(input.data))]])),
  ], { debug: false });
  const instance = await WebAssembly.instantiate(module, { wasi_snapshot_preview1: wasi.wasiImport });
  const code = wasi.start(instance as Parameters<WASI["start"]>[0]);
  if (code !== 0) throw new Error(stderr.join("\n") || `Decompiler exited with code ${code}`);
  const result = stdout.join("\n").trim();
  if (!result) throw new Error("Decompiler returned no source code");
  return result;
}
