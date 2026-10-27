import { existsSync } from "node:fs";
import { copyFile, cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { need } from "./lib.ts";

const root = join(import.meta.dirname, "..");
const source = join(root, ".ddc", "source");
const commit = "ad6227029e60c723fc33e52d56a782622e6f6f74";
const output = join(root, "gui", "public", "ddc");
function run(args: string[], cwd = source) {
  execFileSync(args[0], args.slice(1), { cwd, stdio: "inherit", env: {
    ...process.env, CARGO_BUILD_JOBS: "2", CARGO_PROFILE_RELEASE_DEBUG: "0", CARGO_PROFILE_RELEASE_LTO: "false",
    RUSTC: execFileSync(need("rustup"), ["which", "--toolchain", "stable", "rustc"], { encoding: "utf8" }).trim(),
  } });
}
await mkdir(join(root, ".ddc"), { recursive: true });
if (!existsSync(join(source, ".git"))) {
  run([need("git"), "clone", "https://github.com/ejfkdev/ddc.git", source], root);
}
const actual = execFileSync(need("git"), ["rev-parse", "HEAD"], { cwd: source, encoding: "utf8" }).trim();
if (actual !== commit) {
  run([need("git"), "fetch", "--depth", "1", "origin", commit]);
  run([need("git"), "checkout", "--detach", commit]);
}
await cp(join(root, "externals", "ddc"), join(source, "crates", "igf-ddc"), { recursive: true });
const manifest = join(source, "Cargo.toml");
const toml = await readFile(manifest, "utf8");
if (!toml.includes('"crates/igf-ddc"')) await writeFile(manifest, toml.replace('members = [', 'members = ["crates/igf-ddc", '));
const classdec = join(source, "crates", "ddc-dec", "src", "classdec.rs");
const code = await readFile(classdec, "utf8");
const guard = "if class_is_risky(pool, class) {";
const patched = 'if cfg!(not(target_arch = "wasm32")) && class_is_risky(pool, class) {';
if (!code.includes(guard) && !code.includes(patched)) throw new Error("DDC scheduling adapter no longer matches upstream");
await writeFile(classdec, code.replace(guard, patched));
run([need("rustup"), "run", "stable", "cargo", "build", "--release", "--target", "wasm32-wasip1", "-p", "igf-ddc"]);
await mkdir(output, { recursive: true });
await copyFile(join(source, "target", "wasm32-wasip1", "release", "igf-ddc.wasm"), join(output, "ddc.wasm"));
await copyFile(join(source, "LICENSE"), join(output, "LICENSE"));
await writeFile(join(output, "version.json"), JSON.stringify({ commit }));
console.log(`DDC ${commit.slice(0, 7)} → ${output}`);
