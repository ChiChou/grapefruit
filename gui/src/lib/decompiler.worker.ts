import { run } from "./decompiler/runtime";
import type { Input } from "./decompiler";

self.onmessage = async ({ data }: MessageEvent<Input>) => {
  try {
    const engine = data.target === "dex" ? "ddc" : "kuna";
    const response = await fetch(`/${engine}/${engine}.wasm`);
    if (!response.ok) throw new Error(`${engine} assets are unavailable. Run npm run build:${engine}.`);
    const module = await WebAssembly.compile(await response.arrayBuffer());
    let bundle: Record<string, string> = {};
    if (engine === "kuna") {
      const specs = await fetch("/kuna/specs.json");
      if (!specs.ok) throw new Error("Kuna processor specifications are unavailable");
      bundle = await specs.json();
    }
    self.postMessage({ code: await run(module, bundle, data) });
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : String(error) });
  }
};
