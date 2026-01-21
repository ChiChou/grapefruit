import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";

import app from "./app.ts";
import attach from "./ws.ts";

if (process.env.NODE_ENV !== "development") {
  const dist = new URL("../gui/dist", import.meta.url).pathname;
  app.use("/assets/*", serveStatic({ root: dist }));
  app.use("/*", serveStatic({ root: dist, path: "index.html" }));
}

const server = serve(
  {
    fetch: app.fetch,
    port: parseInt(process.env.PORT!, 10) || 31337,
  },
  (info) => {
    const host = info.address === "::" ? "localhost" : info.address;
    console.info(`Server is running on http://${host}:${info.port}`);
    attach(server);
  },
);

process
  .on("uncaughtException", (err) => {
    console.error("Uncaught Exception:", err);
  })
  .on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection at:", promise, "reason:", reason);
  })
  .on("SIGINT", () => {
    server.close();
  })
  // nodejs --watch will send this signal on file changes
  //
  // note: do not use bun for dev server now
  // https://github.com/oven-sh/bun/issues/25721
  .on("SIGTERM", () => {
    server.close();
  });
