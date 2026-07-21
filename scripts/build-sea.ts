import { createHash } from "node:crypto";
import { chmod, copyFile, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import { need, npm, run } from "./lib.ts";

const root = path.join(import.meta.dirname, "..");
const seaDir = path.join(root, "build", "sea");
const releaseDir = path.join(root, "build", "Release");
const fuse = "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2";

async function files(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(
    entries.map((entry) => {
      const file = path.join(dir, entry.name);
      return entry.isDirectory() ? files(file) : [file];
    }),
  );
  return nested.flat().sort();
}

async function binding(pkg: string, name: string) {
  const dir = path.join(root, "node_modules", pkg);
  const found = (await files(dir)).find((file) => path.basename(file) === name);
  if (found) return found;
  throw new Error(`Unable to find ${name} in ${dir}; run npm install first`);
}

async function main() {
  if (process.argv.length > 2) {
    throw new Error("The Node.js SEA build targets the current platform only");
  }

  await rm(seaDir, { recursive: true, force: true });
  await mkdir(seaDir, { recursive: true });
  await mkdir(releaseDir, { recursive: true });

  run([process.execPath, path.join(root, "scripts", "fetch-r2-wasm.ts")], root);
  run([npm, "exec", "--", "tsdown", "--config", "tsdown.sea.config.ts"], root);

  const roots = ["gui/dist", "agent/dist", "drizzle", "skills"];
  const appFiles = (
    await Promise.all(roots.map((dir) => files(path.join(root, dir))))
  )
    .flat()
    .concat(path.join(root, "radare2.wasm"));

  const relative = appFiles.map((file) => path.relative(root, file).split(path.sep).join("/"));
  const native = {
    sqlite: await binding("better-sqlite3", "better_sqlite3.node"),
    frida16: await binding("frida16", "frida_binding.node"),
    frida17: await binding("frida", "frida_binding.node"),
  };

  const hash = createHash("sha256");
  for (const file of [...appFiles, ...Object.values(native)]) {
    hash.update(await readFile(file));
  }

  const manifest = {
    id: hash.digest("hex").slice(0, 16),
    files: relative,
    native: {
      sqlite: "native/better_sqlite3.node",
      frida16: "native/frida16.node",
      frida17: "native/frida17.node",
    },
  };
  const manifestPath = path.join(seaDir, "manifest.json");
  await writeFile(manifestPath, JSON.stringify(manifest));

  const assets = Object.fromEntries(
    relative.map((file, index) => [`files/${file}`, appFiles[index]]),
  );
  Object.assign(assets, {
    "manifest.json": manifestPath,
    "native/sqlite.node": native.sqlite,
    "native/frida16.node": native.frida16,
    "native/frida17.node": native.frida17,
  });

  const blob = path.join(seaDir, "sea-prep.blob");
  const configPath = path.join(seaDir, "sea-config.json");
  await writeFile(
    configPath,
    JSON.stringify({
      main: path.join(seaDir, "sea.cjs"),
      output: blob,
      disableExperimentalSEAWarning: true,
      useSnapshot: false,
      useCodeCache: false,
      execArgv: ["--disable-warning=ExperimentalWarning"],
      assets,
    }),
  );
  run([process.execPath, "--experimental-sea-config", configPath], root);

  const platform = process.platform === "win32" ? "windows" : process.platform;
  const ext = process.platform === "win32" ? ".exe" : "";
  const output = path.join(
    releaseDir,
    `igf-${platform}-${process.arch}${ext}`,
  );
  await copyFile(process.execPath, output);

  if (process.platform === "darwin") {
    run([need("codesign"), "--remove-signature", output]);
  }

  const args = [
    "exec",
    "--",
    "postject",
    output,
    "NODE_SEA_BLOB",
    blob,
    "--sentinel-fuse",
    fuse,
  ];
  if (process.platform === "darwin") {
    args.push("--macho-segment-name", "NODE_SEA");
  }
  run([npm, ...args], root);

  if (process.platform === "darwin") {
    run([need("codesign"), "--sign", "-", output]);
  } else if (process.platform !== "win32") {
    await chmod(output, 0o755);
  }

  console.log(`built ${output}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
