// build .d.ts for monaco editor

import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

async function wrap(urls: Record<string, string>) {
  const entries = await Promise.all(
    Object.entries(urls).map(async ([key, url]) => {
      const response = await fetch(url);
      if (!response.ok) throw new Error(`Failed to fetch from ${url}`);
      return [key + ".d.ts", await response.text()] as const;
    }),
  );

  return Object.fromEntries(entries);
}

async function main(version: "16" | "17") {
  if (version === "16") {
    return wrap({
      gum: "https://cdn.jsdelivr.net/npm/@types/frida-gum@18/index.d.ts",
    });
  } else if (version === "17") {
    const urls = {
      gum: "@types/frida-gum/index.d.ts",
      objc: "frida-objc-bridge/index.d.ts",
      java: "frida-java-bridge/index.d.ts",
      swift: "frida-swift-bridge/dist/index.d.ts",
    };

    const result = await wrap(
      Object.fromEntries(
        Object.entries(urls).map(([key, url]) => [
          key,
          import.meta.resolve(url),
        ]),
      ),
    );

    result["globals.d.ts"] = [
      'declare const ObjC: typeof import("frida-objc-bridge").default;',
      'declare const Java: typeof import("frida-java-bridge").default;',
      'declare const Swift: typeof import("frida-swift-bridge").default;',
    ].join("\n");

    return result;
  }
}

const outDir = join(import.meta.dirname, "../dist/types");
await mkdir(outDir, { recursive: true });

for (const version of ["16", "17"] as const) {
  const result = await main(version);
  const outPath = join(outDir, `frida${version}.json`);
  await writeFile(outPath, JSON.stringify(result));
  console.log(`wrote ${outPath}`);
}
