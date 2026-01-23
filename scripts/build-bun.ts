#! /usr/bin/env bun

import path from "node:path";
import cp from "node:child_process";

import { $ } from "bun";
import { patch } from "./utils";

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

function prebuild(cwd: string, platform?: string, arch?: string) {
  cp.spawnSync(
    process.execPath,
    [
      path.join(root, "node_modules", ".bin", "prebuild-install"),
      "-r",
      "napi",
      "--arch",
      arch || process.arch,
      "--platform",
      platform || process.platform,
    ],
    {
      cwd,
      stdio: "inherit",
    },
  );
}

function bunBuild(target?: string) {
  const name = target ? target.replace("bun-", "igf-") : "igf";
  const targetArgs: string[] = [];

  if (target) {
    console.log("build bun binary for:", target);

    targetArgs.push("--target");
    targetArgs.push(target);
  }

  cp.spawnSync(
    process.execPath,
    [
      "build",
      ...targetArgs,
      path.join(root, "src", "index.ts"),
      path.join(root, "assets.tgz"),
      "--compile",
      "--outfile",
      path.join(root, "build", "Release", name),
    ],
    {
      stdio: "inherit",
    },
  );
}

async function main() {
  console.warn("this script is experimental and not well tested");

  const mode = process.argv[2] ?? "current";
  const cross = mode === "cross";

  if (!["current", "cross"].includes(mode)) {
    console.error("Usage: bun scripts/cross-build.ts [current|cross]");
    process.exit(1);
  }

  await $`bun i`;
  await $`bun run install:bun`;

  // will trigger a weird bug
  //
  //     path: "./igf/undefined",
  //  syscall: "open",
  //    errno: -2,
  //     code: "ENOENT"
  //
  // for (const cwd of [".", "gui", "agent"]) {
  //   await $`bun i`.cwd(cwd);
  // }

  // bun patch only works when node_modules is empty

  await patch("frida", true);
  await patch("frida16", true);

  // Not tested on Windows. This script is only intended for CI
  await $`tar czf assets.tgz gui/dist agent/dist`;

  for (const name of ["frida", "frida16"]) {
    const cwd = path.join(root, "node_modules", name);

    if (cross) {
      for (const [target, [platform, arch]] of Object.entries(bunTargets)) {
        console.log("install prebuild for:", target, platform, arch);

        prebuild(cwd, platform, arch);
        bunBuild(target);
      }
    }

    // restore prebuild
    prebuild(cwd);
  }

  if (!cross) {
    bunBuild();
  }
}

main();
