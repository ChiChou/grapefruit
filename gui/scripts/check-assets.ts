import { access } from "node:fs/promises";
import { resolve } from "node:path";

const root = process.argv[2] ? resolve(process.argv[2]) : resolve(import.meta.dirname, "..", "public");
for (const file of ["kuna/kuna.wasm", "kuna/specs.json", "kuna/LICENSE", "kuna/NOTICE", "ddc/ddc.wasm", "ddc/LICENSE"]) {
  await access(resolve(root, file)).catch(() => {
    throw new Error(`Missing ${file}. Run npm run build:kuna and npm run build:ddc at the repository root, then rebuild the GUI.`);
  });
}
