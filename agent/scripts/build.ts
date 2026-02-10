#!/usr/bin/env bun

import { $ } from "bun";
import { styleText } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";

await $`bun run type`;

await fs.mkdir(path.join("dist", "bridges"), { recursive: true });

const list = ["java", "objc", "swift"] as const;
await Promise.all(
  list.map(async (name) => {
    console.log(
      styleText("blue", "compiling bridge:"),
      styleText("yellow", name),
    );
    await $`bunx frida-compile ${path.join(
      "src",
      "bridges",
      name + ".ts",
    )} -o ${path.join("dist", "bridges", name + ".js")}`;
  }),
);

const metadata = await import("../package.json", { with: { type: "json" } });

await Promise.all(
  Object.keys(metadata.scripts)
    .filter((name) => name.startsWith("build:"))
    .map((name) => $`bun run ${name}`),
);

console.log(styleText("green", "all build tasks finished"));
