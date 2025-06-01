import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const root = path.join(
  path.dirname(fileURLToPath(new URL(import.meta.url))),
  "..",
);

export async function* allBuildScripts(): AsyncGenerator<[string, string]> {
  const pkg = JSON.parse(
    await fs.promises.readFile(path.join(root, "package.json"), "utf8"),
  );

  for (const [name, cmd] of Object.entries(
    pkg.scripts as Record<string, string>,
  )) {
    if (name.startsWith("build:")) yield [name, cmd];
  }
}
