import { parseArgs } from "node:util";

import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";

import app from "./app.ts";
import attach from "./ws.ts";
import env from "./lib/env.ts";
import { asset } from "./lib/assets.ts";
import { schema } from "./lib/cli.ts";

{
  const args = parseArgs(schema);
  if (args.values.help) {
    console.log(`
Usage: igf [options]

Options:
  --frida <16 | 17>  Specify Frida version to use (default: 17)
  --host <host>      Host to bind the server (default: localhost)
  --port <port>      Port to bind the server (default: 31337)
  --help, -h         Show this help message
    `);
    process.exit(0);
  }

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
  (info) => {
    const host = info.family === "IPv6" ? `[${info.address}]` : info.address;
    console.info(`Server is running on http://${host}:${info.port}`);
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
