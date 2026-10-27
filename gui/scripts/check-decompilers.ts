import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { run } from "../src/lib/decompiler/runtime.ts";
import { snapshot, target, type Target } from "../src/lib/decompiler.ts";
import { elf, macho } from "./fixtures/native.ts";

const root = join(import.meta.dirname, "..", "public");
const module = await WebAssembly.compile(await readFile(join(root, "kuna", "kuna.wasm")));
const bundle = JSON.parse(await readFile(join(root, "kuna", "specs.json"), "utf8"));
const families = new Set(Object.keys(bundle).map((path) => path.split("/")[2]));
assert.deepEqual([...families].sort(), ["AARCH64", "ARM", "x86"]);
for (const value of Object.values(bundle) as string[]) {
  const xml = Buffer.from(value, "base64").toString();
  assert(!xml.includes('id="x86:LE:16:'), "16-bit x86 must not be advertised");
}
assert.equal(target("mips", 32), null);
assert.equal(target("x86", 16), null);
assert.equal(target("arm", 16), "thumb");
assert.equal(target("arm", 64), "arm64");

const cases: [Target, string][] = [
  ["x86", "b82a000000c3"],
  ["x64", "b82a000000c3"],
  ["arm", "2a00a0e31eff2fe1"],
  ["thumb", "2a207047"],
  ["arm64", "40058052c0035fd6"],
  ["arm64e", "3f2303d540058052bf2303d5c0035fd6"],
];
for (const [target, hex] of cases) {
  const data = Uint8Array.from(Buffer.from(hex, "hex")).buffer;
  const output = await run(module, bundle, { data, target, base: "0x1000", address: "0x1000" });
  assert.match(output, /return (?:42|0x2a);/, `${target}: ${output}`);
  console.log(`${target}: decompiled return 42`);
  const machine = target === "x86" ? 3 : target === "x64" ? 62 : target.startsWith("arm64") ? 183 : 40;
  const file = target === "arm64e" ? macho(new Uint8Array(data)) : elf(machine, new Uint8Array(data), target === "x64" || target === "arm64", target === "thumb");
  const source = await run(module, bundle, { data: file, target, address: target === "arm64e" ? "0x2000" : "0x1000", thumb: target === "thumb" });
  assert.match(source, /return (?:42|0x2a);/, `${target} file: ${source}`);
  console.log(`${target}: loaded executable and decompiled return 42`);
}

const calls: string[] = [];
const live = await snapshot(async (command) => {
  calls.push(command);
  if (command === "e asm.arch") return "arm\n";
  if (command === "e asm.bits") return "32\n";
  if (command === "afij @ 0x1000") return JSON.stringify([{ offset: 4096, size: 4, bits: 16 }]);
  if (command === "p8 4 @ 0x1000") return "2a207047\n";
  throw new Error(command);
}, "0x1001");
assert.equal(live.thumb, true);
assert.equal(live.address, "0x1000");
assert.equal(live.base, "0x1000");
assert(calls.includes("p8 4 @ 0x1000"));
assert.match(await run(module, bundle, live), /return (?:42|0x2a);/);
await assert.rejects(snapshot(async () => "", "0x1000;!cmd"), /Invalid function address/);

const ddc = await WebAssembly.compile(await readFile(join(root, "ddc", "ddc.wasm")));
const data = Uint8Array.from(await readFile(join(import.meta.dirname, "fixtures", "hello.dex"))).buffer;
const java = await run(ddc, {}, { data, target: "dex", address: "0x22c" });
assert.match(java, /class Greeter/);
assert.match(java, /return "hi " \+ this.name;/);
const hello = await run(ddc, {}, { data, target: "dex", address: "0x248" });
assert.match(hello, /class Hello/);
assert.match(hello, /System.out.println\(new Greeter\("world"\).greet\(\)\)/);
await assert.rejects(run(ddc, {}, { data, target: "dex", address: "0xffffff" }), /No DEX method body/);
console.log("DEX: reconstructed Greeter and Hello by instruction offset; invalid method rejected");
