import fs from "node:fs/promises";
import path from "node:path";
import env from "./env";

import paths from "./paths";
import { readFile } from "node:fs/promises";

// bun does not support embedded directory as a tree
// extract assets when it's not present

async function extract(): Promise<string> {
  if (!globalThis.Bun) throw new Error("bun runtime required");

  // @ts-ignore embed file has no typing
  const tar: { default: string } = await import("../../assets.tgz", {
    with: { type: "file" },
  });

  // this name includes hash
  const name = tar.default.split("/").pop()!;
  const output = path.join(paths.cache, name);
  console.log("assets directory:", output);
  const exists = await fs
    .stat(output)
    .then((s) => s.isDirectory())
    .catch((e) => {
      if (e.code === "ENOENT") return false;
      throw e;
    });

  if (!exists) {
    const tarball = await Bun.file(tar.default).bytes();
    const archive = new Bun.Archive(tarball);
    await archive.extract(output);
  }

  return output;
}

let assetsRoot: string | null = null;
export async function asset(...components: string[]) {
  if (assetsRoot == null) {
    if (env.bunSEA) {
      assetsRoot = await extract();
    } else {
      // workaround: tsdown flattens directory structure
      const basePath = env.production ? "../" : "../../";
      assetsRoot = new URL(basePath, import.meta.url).pathname;
    }
  }

  return path.join(assetsRoot, ...components);
}

export async function agent(name: string) {
  return asset("agent", "dist", name).then((p) => readFile(p + ".js", "utf8"));
}
