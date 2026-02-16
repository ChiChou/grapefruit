#!/usr/bin/env bun

import { $ } from "bun";
import { styleText } from "node:util";
import fs from "node:fs/promises";
import path from "node:path";

await $`bun run type`;

async function buildBridges() {
  const list = ["java", "objc", "swift"] as const;

  const dir = path.join("dist", "bridges");
  await fs.mkdir(dir, { recursive: true });

  // We cannot compile those bridges, since frida-compile is not giving pure valid javascript
  // for IIFE. For now, lock the package verion and download from pypi

  const pypi = await fetch("https://pypi.org/pypi/frida-tools/json");
  if (!pypi.ok)
    throw new Error(`Failed to fetch frida-tools metadata: ${pypi.statusText}`);

  const pypiData = (await pypi.json()) as { urls: { url: string }[] };
  const url = pypiData.urls.at(0)?.url;

  if (!url) throw new Error("could not locate latest frida-tools package");

  // download tar.gz
  const response = await fetch(url);
  const tgz = await response.blob();
  const archive = new Bun.Archive(tgz);
  const files = await archive.files();
  const names = list.map((name) => `${name}.js`);

  for (const [p, file] of files) {
    const basename = p.split("/").at(-1);
    if (basename && names.includes(basename)) {
      const out = path.join(dir, basename);
      Bun.write(out, await file.arrayBuffer());
      console.log(`downloaded bridge ${out}`);
    }
  }
}

await buildBridges();

const metadata = await import("../package.json", { with: { type: "json" } });

await Promise.all(
  Object.keys(metadata.scripts)
    .filter((name) => name.startsWith("build:"))
    .map((name) => $`bun run ${name}`),
);

console.log(styleText("green", "all build tasks finished"));
