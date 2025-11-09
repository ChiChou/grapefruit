import path from "node:path";
import { promises as fsp } from "node:fs";

export async function readAgent(name: string) {
  const scriptPath = path.join(
    import.meta.dirname,
    "..",
    "..",
    "agent",
    "dist",
    `${name}.js`,
  );

  return fsp.readFile(scriptPath, "utf8");
}
