import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";

import app from "./app.ts";
import attach from "./ws.ts";

{
  const root = "./gui/dist";
  const frontend = new URL(root, import.meta.url).pathname;

  // bug: when compiled by bun single-file executable, the runtime will set
  // NODE_ENV to development. Does it make any sense?

  if (frontend.startsWith("/$bunfs/root")) {
    app.use("/assets/*", serveStatic({ root }));
    app.use("/*", serveStatic({ root, path: "index.html" }));
  }

  if (process.env.NODE_ENV !== "development") {
    app.use("/assets/*", serveStatic({ root: frontend }));
    app.use("/*", serveStatic({ root: frontend, path: "index.html" }));
  }
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

for (const sig of ["SIGINT", "SIGTERM", "SIGBEAK"]) {
  process.on(sig, () => {
    console.log("received signal", sig);
    server.close();
  });
}

process
  .on("uncaughtException", (err) => {
    console.error("Uncaught Exception:", err);
  })
  .on("unhandledRejection", (reason, promise) => {
    console.error("Unhandled Rejection at:", promise, "reason:", reason);
  });
