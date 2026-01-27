#! /usr/bin/env bun

import path from "node:path";
import { $, Glob, type BunFile } from "bun";

const bunTargets: Record<string, [string, string]> = {
  "bun-linux-x64": ["linux", "x64"],
  // "bun-linux-arm64": ["linux", "arm64"],
  "bun-windows-x64": ["win32", "x64"],
  "bun-darwin-x64": ["darwin", "x64"],
  "bun-darwin-arm64": ["darwin", "arm64"],
  // "bun-linux-x64-musl": ["linux", "x64"],
  // "bun-linux-arm64-musl": ["linux", "arm64"],
};

const root = path.join(import.meta.dirname, "..");

async function prebuild(
  cwd: string,
  platform: string = process.platform,
  arch: string = process.arch,
) {
  console.log("prebuild", cwd, "for", platform, arch);
  const binary = path.join(root, "node_modules", ".bin", "prebuild-install");
  await $`${process.execPath} ${binary} -r napi --arch ${arch} --platform ${platform}`.cwd(
    cwd,
  );
}

async function bunBuild(target?: string) {
  const name = target ? target.replace("bun-", "igf-") : "igf";
  const targetArgs: string[] = [];

  if (target) {
    console.log("build bun binary for:", target);
    targetArgs.push("--target");
    targetArgs.push(target);
  }

  await $`${process.execPath} build ${targetArgs} ${path.join(root, "src", "index.ts")} ${path.join(root, "assets.tgz")} --compile --outfile ${path.join(root, "build", "Release", name)}`;
}

async function main() {
  console.warn("this script is experimental and not well tested");

  const mode = process.argv[2] ?? "current";
  const cross = mode === "cross";

  if (!["current", "cross"].includes(mode)) {
    console.error("Usage: bun scripts/cross-build.ts [current|cross]");
    process.exit(1);
  }

  await $`tar cvf assets.tgz gui/dist agent/dist`;

  for (const name of ["frida", "frida16"]) {
    const cwd = path.join(root, "node_modules", name);

    if (cross) {
      for (const [target, [platform, arch]] of Object.entries(bunTargets)) {
        await prebuild(cwd, platform, arch);
        await bunBuild(target);
      }
    }

    // restore prebuild
    await prebuild(cwd);
  }

  if (!cross) {
    await bunBuild();
  }
}

main();
