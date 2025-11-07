import path from "path";
import { fileURLToPath } from "url";

export default async function getVersion(pkg: string) {
  const {
    default: { version },
  } = await pkgJSON(pkg);
  return version;
}

async function pkgJSON(pkg: string): Promise<{ default: { version: string } }> {
  return import(path.join(pkg, "package.json")).catch((_) => {
    const abs = fileURLToPath(import.meta.resolve(pkg));
    const needle = "node_modules" + path.sep;
    const index = abs.lastIndexOf(needle);
    const prefix = abs.substring(0, index + needle.length);
    return import(path.join(prefix, pkg, "package.json"), {
      with: { type: "json" },
    });
  });
}
