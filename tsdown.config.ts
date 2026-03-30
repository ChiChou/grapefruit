import { defineConfig } from "tsdown";

const env = {
  NODE_ENV: "production",
  SQLITE: "better-sqlite3",
};

export default defineConfig([
  {
    entry: { index: "src/index.ts" },
    format: "esm",
    external: ["../../assets.tgz"],
    env,
  },
  {
    entry: { bin: "src/bin.ts" },
    format: "esm",
    external: ["../../assets.tgz"],
    banner: { js: "#!/usr/bin/env node" },
    env,
  },
]);
