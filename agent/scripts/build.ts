#!/usr/bin/env bun

import path from "path";
import cp from "child_process";
import assert from "assert";
import fs, { glob } from "fs/promises";

async function compile(major: number, input: string, output: string) {
  const mapping = {
    16: 18,
    17: 19,
  };

  const compiler = mapping[major];
  assert(compiler, `Unsupported version: ${major}`);

  const args = [
    "-y",
    `frida-compile@${compiler}`,
    input,
    "-o",
    `${output}@${major}.js`,
    "-c",
  ];

  console.debug("npx", args.join(" "));

  await new Promise<void>((resolve, reject) => {
    // todo: add bun, pnpm, etc..
    const child = cp.spawn("npx", args, {
      stdio: "inherit",
      shell: true,
    });

    child.on("exit", (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`frida-compile exited with code ${code}`));
      }
    });
  });
}

async function main() {
  console.info("Hacky build script to generate frida agent for both 16 and 17");

  const dist = "dist";
  await fs.rm(dist, { recursive: true }).catch(() => {});
  await fs.mkdir(dist);

  const dir = "patched";
  await fs.rm(dir, { recursive: true }).catch(() => {});

  await fs.mkdir(dir);
  await fs.writeFile(path.join(dir, ".gitignore"), "*\n");

  await fs.cp("src", dir, { recursive: true });
  for (const platform of ["fruity", "droid"]) {
    const parent = path.join("src", platform);
    // compile for 16
    {
      const main = path.join(parent, "index.ts");
      await compile(16, main, path.join(dist, platform));
    }

    const bannedFns = [
      "Memory.read",
      "Module.ensureInitialized(",
      "Module.findBaseAddress(",
      "Module.getBaseAddress(",
      "Module.findExportByName(",
      "Module.getExportByName(",
      "Module.findSymbolByName(",
      "Module.getSymbolByName(",
    ];

    const tmp = path.join(dir, platform);
    const wildcard = path.join(tmp, "**", "*.ts");
    for await (const entry of glob(wildcard)) {
      const content = await fs.readFile(entry, "utf-8");

      for (const fn of bannedFns) {
        if (content.includes(fn)) {
          throw new Error(`Banned function "${fn}" found in ${entry}`);
        }
      }

      // string match
      // todo: search for banned functions
      if (content.includes("Java.")) {
        await fs.writeFile(
          entry,
          `import Java from "frida-java-bridge";\n${content}`,
        );
      } else if (content.includes("ObjC.")) {
        await fs.writeFile(
          entry,
          `import ObjC from "frida-objc-bridge";\n${content}`,
        );
      }
    }

    const main = path.join(tmp, "index.ts");
    await compile(17, main, path.join(dist, platform));
  }
  if (!process.env.DEBUG) await fs.rm(dir, { recursive: true }).catch(() => {});
}

main();
