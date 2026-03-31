import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";

import app from "./app.ts";
import attach from "./ws.ts";
import env from "./lib/env.ts";
import getVersion from "./lib/version.ts";
import { asset } from "./lib/assets.ts";

{
  if (!["16", "17"].includes(String(env.frida))) {
    console.error(
      "Invalid Frida version specified. Use --frida 16 or --frida 17.",
    );
    process.exit(1);
  }
}

{
  function serveWeb(root: string) {
    app.use("/assets/*", serveStatic({ root }));
    app.use("/*", serveStatic({ root, path: "index.html" }));
  }

  // bug: when compiled by bun single-file executable, the runtime will set
  // NODE_ENV to "development". Does it make any sense?

  if (env.bunSEA || !env.dev) {
    serveWeb(await asset("gui", "dist"));
  }
}

const server = serve(
  {
    fetch: app.fetch,
    port: env.port,
    hostname: env.host,
  },
  async (info) => {
    const {
      default: { version },
    } = await import("../package.json", { with: { type: "json" } });
    const fridaVer = await getVersion(env.frida === 16 ? "frida16" : "frida");
    const host = info.family === "IPv6" ? `[${info.address}]` : info.address;

    // prettier-ignore
    console.info(`
Grapefruit v${version} (Frida ${fridaVer})

  Web UI  http://${host}:${info.port}
  API     http://${host}:${info.port}/api${env.dev ? "\n  Mode    development" : ""}
`);

    attach(server);
  },
);

for (const sig of ["SIGINT", "SIGTERM", "SIGBEAK"]) {
  process.on(sig, () => {
    console.log("received signal", sig);
    server.close();

    // force close
    process.exit();
  });
}

process
  .on("uncaughtException", (err) => {
    console.error("Uncaught Exception:", err);
  })
  .on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection at:", promise, "reason:", reason);
  });
