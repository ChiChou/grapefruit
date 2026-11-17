import { spawnSync } from "node:child_process";
import fs from "node:fs/promises";
import path from "node:path";
import { styleText } from "node:util";

import { unzipSync } from "fflate";

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
  // Download the prebuilt scripts from the frida-tools wheel. The source archive
  // contains the bridge TypeScript sources but not the compiled JavaScript.
  const pypi = await fetch("https://pypi.org/pypi/frida-tools/json");
  if (!pypi.ok)
    throw new Error(`Failed to fetch frida-tools metadata: ${pypi.statusText}`);

  const data = (await pypi.json()) as {
    urls: { url: string; packagetype: string }[];
  };
  const url = data.urls.find((file) => file.packagetype === "bdist_wheel")?.url;
  if (!url) throw new Error("could not locate frida-tools wheel");

  const response = await fetch(url);
  if (!response.ok)
    throw new Error(`Failed to download frida-tools: ${response.statusText}`);
  const files = unzipSync(new Uint8Array(await response.arrayBuffer()), {
    filter: (file) =>
      file.name.startsWith("frida_tools/bridges/") &&
      names.has(path.basename(file.name)),
  });
  for (const [entry, data] of Object.entries(files)) {
    const name = path.basename(entry);
    const out = path.join(dir, name);
    await fs.writeFile(out, data);
    found.add(name);
    console.log(`downloaded bridge ${out}`);
  }

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
