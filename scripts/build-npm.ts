import fs from "node:fs/promises";

async function main() {
  // undo patches from bun
  const resolve = (relative: string) =>
    new URL(relative, import.meta.url).pathname;

  await fs.writeFile(resolve("../assets.tgz"), "");
}

main();
