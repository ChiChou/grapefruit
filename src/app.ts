import { readFile } from "node:fs/promises";

import { Hono } from "hono";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";

import getVersion from "./lib/version.ts";
import env from "./lib/env.ts";
import { asset } from "./lib/assets.ts";

import apkRoutes from "./routes/apk.ts";
import deviceRoutes from "./routes/devices.ts";
import transferRoutes from "./routes/transfer.ts";
import dataRoutes from "./routes/data.ts";
import llmRoutes from "./routes/llm.ts";
import r2Routes from "./routes/r2.ts";

const app = new Hono();

app.use(logger());
app.use("/api/*", prettyJSON());

const api = new Hono();

api.get("/version", async (c) => {
  const {
    default: { version },
  } = await import("../package.json", {
    with: { type: "json" },
  });

  return c.json({
    frida: await getVersion(env.frida === 16 ? "frida16" : "frida"),
    igf: version,
  });
});

api.get("/d.ts/pack", async (c) => {
  const p = await asset("agent", "dist", "types", `frida${env.frida}.json`);
  try {
    const data = await readFile(p, "utf8");
    return c.json(JSON.parse(data));
  } catch {
    return c.notFound();
  }
});

api.route("/", apkRoutes);
api.route("/", deviceRoutes);
api.route("/", transferRoutes);
api.route("/", dataRoutes);
api.route("/", llmRoutes);
api.route("/", r2Routes);

app.route("/api", api);

// Serve radare2.wasm with aggressive caching (version-pinned, SHA256-verified)
app.get("/radare2.wasm", async (c) => {
  const wasmPath = await asset("radare2.wasm");
  const data = await readFile(wasmPath);
  return c.body(data, 200, {
    "Content-Type": "application/wasm",
    "Cache-Control": "public, max-age=31536000, immutable",
    "Content-Length": String(data.byteLength),
    "X-R2-Version": "6.1.2",
  });
});

export default app;
