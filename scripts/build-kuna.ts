import { existsSync } from "node:fs";
import { copyFile, cp, mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { need } from "./lib.ts";

const root = join(import.meta.dirname, "..");
const source = join(root, ".kuna", "source");
const commit = "5a1033c9077c0c7004259b3595001585f41017a4";
const output = join(root, "gui", "public", "kuna");
const engine = join(source, "decompiler");
const processors = ["x86", "ARM", "AARCH64"];

function run(args: string[], cwd = engine) {
  execFileSync(args[0], args.slice(1), { cwd, stdio: "inherit", env: { ...process.env, CARGO_BUILD_JOBS: "2", RUSTC: execFileSync(need("rustup"), ["which", "--toolchain", "stable", "rustc"], { encoding: "utf8" }).trim() } });
}

await mkdir(join(root, ".kuna"), { recursive: true });
if (!existsSync(join(source, ".git"))) {
  run([need("git"), "clone", "--filter=blob:none", "https://github.com/noelo-Lab/kuna.git", source], root);
}
const actual = execFileSync(need("git"), ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
if (actual !== commit) {
  run([need("git"), "fetch", "--depth", "1", "origin", commit], source);
  run([need("git"), "checkout", "--detach", commit], source);
}
await cp(join(root, "externals", "kuna"), join(engine, "crates", "igf-kuna"), { recursive: true });
const rustup = need("rustup");
run([rustup, "run", "stable", "cargo", "build", "--release", "-p", "kuna-slacomp"]);
run([rustup, "run", "stable", "cargo", "build", "--release", "--target", "wasm32-wasip1", "-p", "igf-kuna"]);
await mkdir(output, { recursive: true });
await copyFile(join(engine, "target", "wasm32-wasip1", "release", "igf-kuna.wasm"), join(output, "kuna.wasm"));

const bundle: Record<string, string> = {};
for (const processor of processors) {
  const rel = `Ghidra/Processors/${processor}/data/languages`;
  const dir = join(source, "specs", rel);
  const names = await readdir(dir);
  const needed = new Set<string>();
  for (const name of names.filter((n) => n.endsWith(".ldefs"))) {
    const xml = await readFile(join(dir, name), "utf8");
    const languages = [...xml.matchAll(/<language\b[\s\S]*?<\/language>/g)]
      .map((m) => m[0])
      .filter((s) => /id="(?:x86:LE:(?:32|64):default|ARM:(?:LE|BE):32:v8T?|AARCH64:(?:LE|BE):64:(?:v8A|AppleSilicon))"/.test(s));
    if (!languages.length) continue;
    bundle[`${rel}/${name}`] = Buffer.from(`<language_definitions>\n${languages.join("\n")}\n</language_definitions>`).toString("base64");
    for (const language of languages) {
      for (const match of language.matchAll(/(?:slafile|processorspec|spec)="([^"]+)"/g)) needed.add(match[1]);
      for (const match of language.matchAll(/name="([^"]+\.(?:dwarf|register\.info))"/g)) needed.add(match[1]);
    }
  }
  for (const name of needed) {
    if (name.endsWith(".sla")) {
      const spec = join(dir, name.replace(/\.sla$/, ".slaspec"));
      run([join(engine, "target", "release", `slacomp${process.platform === "win32" ? ".exe" : ""}`), spec, join(dir, name)], dir);
    }
    bundle[`${rel}/${name}`] = (await readFile(join(dir, name))).toString("base64");
  }
}
await writeFile(join(output, "specs.json"), JSON.stringify(bundle));
for (const name of ["LICENSE", "NOTICE"]) await copyFile(join(source, name), join(output, name));
await writeFile(join(output, "version.json"), JSON.stringify({ commit, processors }));
console.log(`Kuna ${commit.slice(0, 7)}: ${Object.keys(bundle).length} runtime specs → ${output}`);
