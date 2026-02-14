import { Hono } from "hono";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";

import getVersion from "./lib/version.ts";
import env from "./lib/env.ts";

import deviceRoutes from "./routes/devices.ts";
import transferRoutes from "./routes/transfer.ts";
import dataRoutes from "./routes/data.ts";

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

api.route("/", deviceRoutes);
api.route("/", transferRoutes);
api.route("/", dataRoutes);

app.route("/api", api);

export default app;
