import path from "node:path";
import { readFileSync } from "node:fs";
import { defineConfig } from "tsdown";

const lock = JSON.parse(
  readFileSync(new URL("./package-lock.json", import.meta.url), "utf8"),
);

export default defineConfig({
  entry: { sea: "src/sea.ts" },
  format: "cjs",
  outDir: "build/sea",
  clean: false,
  hash: false,
  noExternal: [/.*/],
  inlineOnly: false,
  alias: {
    bindings: path.join(import.meta.dirname, "src", "lib", "sea-bindings.cjs"),
  },
  plugins: [
    {
      name: "sea-frida",
      resolveId(source, importer) {
        if (!importer) return;
        const resolved = path.resolve(path.dirname(importer), source);
        const lib = path.join(import.meta.dirname, "src", "lib");
        if (resolved === path.join(lib, "xvii.ts"))
          return path.join(lib, "xvii-sea.ts");
        if (resolved === path.join(lib, "version.ts"))
          return path.join(lib, "version-sea.ts");
      },
    },
  ],
  env: {
    NODE_ENV: "production",
    IGF_FRIDA16_VERSION: lock.packages["node_modules/frida16"].version,
    IGF_FRIDA17_VERSION: lock.packages["node_modules/frida"].version,
  },
  outputOptions: { codeSplitting: false },
  checks: { legacyCjs: false },
});
