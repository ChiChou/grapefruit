import { spawnSync } from "node:child_process";
import { createWriteStream } from "node:fs";
import fs from "node:fs/promises";
import path from "node:path";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { styleText } from "node:util";
import { createGunzip } from "node:zlib";

import tar from "tar-stream";

const npm = process.platform === "win32" ? "npm.cmd" : "npm";

function run(args: string[]) {
  const result = spawnSync(npm, args, { stdio: "inherit" });
  if (result.error) throw result.error;
  if (result.status) process.exit(result.status);
}

run(["run", "type"]);

async function buildBridges() {
  const names = new Set(["java.js", "objc.js", "swift.js"]);
  const found = new Set<string>();
  const dir = path.join("dist", "bridges");
  await fs.mkdir(dir, { recursive: true });

  // frida-compile does not produce bridge scripts that can run as IIFEs.
  // Download the matching prebuilt scripts from the frida-tools package instead.
  const pypi = await fetch("https://pypi.org/pypi/frida-tools/json");
  if (!pypi.ok)
    throw new Error(`Failed to fetch frida-tools metadata: ${pypi.statusText}`);

  const data = (await pypi.json()) as { urls: { url: string }[] };
  const url = data.urls.at(0)?.url;
  if (!url) throw new Error("could not locate latest frida-tools package");

  const response = await fetch(url);
  if (!response.ok)
    throw new Error(`Failed to download frida-tools: ${response.statusText}`);
  if (!response.body) throw new Error("frida-tools download had no response body");

  const extract = tar.extract();
  extract.on("entry", (header, stream, next) => {
    const name = path.basename(header.name);
    if (!names.has(name)) {
      stream.resume();
      stream.once("end", next);
      return;
    }

    const out = path.join(dir, name);
    pipeline(stream, createWriteStream(out)).then(
      () => {
        found.add(name);
        console.log(`downloaded bridge ${out}`);
        next();
      },
      (error) => extract.destroy(error),
    );
  });

  await pipeline(
    Readable.fromWeb(response.body as import("node:stream/web").ReadableStream),
    createGunzip(),
    extract,
  );

  const missing = [...names].filter((name) => !found.has(name));
  if (missing.length) {
    throw new Error(`frida-tools archive is missing: ${missing.join(", ")}`);
  }
}

await buildBridges();

const metadata = await import("../package.json", { with: { type: "json" } });
for (const name of Object.keys(metadata.default.scripts).filter((name) =>
  name.startsWith("build:"),
)) {
  run(["run", name]);
}

console.log(styleText("green", "all build tasks finished"));
