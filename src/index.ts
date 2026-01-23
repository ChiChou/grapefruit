import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";

import app from "./app.ts";
import attach from "./ws.ts";
import env from "./lib/env.ts";
import { asset } from "./lib/assets.ts";

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
  },
  (info) => {
    const host = info.address === "::" ? "localhost" : info.address;
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
