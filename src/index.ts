import { serve } from "@hono/node-server";

import app from "./app.ts";
import attach from "./ws.ts";

if (process.env.NODE_ENV !== "development") {
  // todo: serve built frontend
}

const server = serve(
  {
    fetch: app.fetch,
    port: parseInt(process.env.PORT!, 10) || 31337,
  },
  (info) => {
    console.info(`Server is running on http://${info.address}:${info.port}`);
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
  .on("SIGTERM", () => {
    server.close();
  });
