import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import env from "./env.ts";

let root: string;

export function asset(...components: string[]) {
  if (!root) {
    const base = env.production ? "../" : "../../";
    root = process.env.IGF_ASSETS_DIR ?? fileURLToPath(new URL(base, import.meta.url));
  }
  return path.join(root, ...components);
}

export async function agent(name: string) {
  return readFile(asset("agent", "dist", name) + ".js", "utf8");
}
