import fs from "node:fs/promises";

import { patch, run } from "./utils.ts";

async function main() {
  // undo patches from bun
  const resolve = (relative: string) =>
    new URL(relative, import.meta.url).pathname;

  await patch("frida", false);
  await patch("frida16", false);

  await run(["npm", "i"], { cwd: resolve("../") });
  await fs.writeFile(resolve("../assets.tgz"), "");
}

main();
