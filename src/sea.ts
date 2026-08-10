import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { getAsset } from "node:sea";

type Manifest = {
  id: string;
  files: string[];
  native: Record<string, string>;
};

async function main() {
  const manifest = JSON.parse(getAsset("manifest.json", "utf8")) as Manifest;
  const root = join(tmpdir(), "igf", manifest.id);

  async function materialize(key: string, file: string) {
    const output = join(root, file);
    if (existsSync(output)) return output;
    await mkdir(dirname(output), { recursive: true });
    await writeFile(output, new Uint8Array(getAsset(key)));
    return output;
  }

  await Promise.all(
    manifest.files.map((file) => materialize(`files/${file}`, file)),
  );

  const frida = process.argv.findIndex((arg) => arg === "--frida");
  const version =
    (frida >= 0 ? process.argv[frida + 1] : undefined) ??
    process.env.FRIDA_VERSION ??
    "17";
  const bindings = {
    frida16: await materialize("native/frida16.node", manifest.native.frida16),
    frida17: await materialize("native/frida17.node", manifest.native.frida17),
  };

  process.env.IGF_ASSETS_DIR = root;
  process.env.IGF_FRIDA_BINDING =
    version === "16" ? bindings.frida16 : bindings.frida17;

  await import("./bin.ts");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
