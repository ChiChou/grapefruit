import frida from "frida";
import { Hono } from "hono";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";
import { createMiddleware } from "hono/factory";

import getVersion from "./lib/version.ts";
import env from "./lib/env.ts";

import {
  app as serializeApp,
  device as serializeDevice,
} from "./lib/serializer.ts";

const manager = frida.getDeviceManager();
const app = new Hono();

app.use(logger());
app.use("/api/*", prettyJSON());

const api = app.basePath("/api");
const getDeviceMiddleware = createMiddleware<{
  Variables: {
    device: frida.Device;
    bundle?: string;
  };
}>(async (c, next) => {
  const deviceId = c.req.param("device");
  if (!deviceId) {
    return c.json({ error: "device not found" }, 404);
  }

  c.set("device", await frida.getDevice(deviceId));
  await next();
});

api
  .get("/version", async (c) => {
    const {
      default: { version },
    } = await import("../package.json", {
      with: { type: "json" },
    });

    return c.json({ frida: await getVersion("frida"), igf: version });
  })
  .get("/devices", async (c) => {
    const skip = new Set(["local", "socket", "barebone"]);
    const devices = await frida.enumerateDevices();
    return c.json(
      devices.filter((dev) => !skip.has(dev.id)).map(serializeDevice),
    );
  })
  .get("/device/:device/apps", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    const apps = await device.enumerateApplications();
    return c.json(apps.map(serializeApp));
  })
  .get("/device/:device/icon/:bundle", async (c) => {
    const deviceId = c.req.param("device");
    const bundle = c.req.param("bundle");

    if (!deviceId) {
      return c.json({ error: "device not found" }, 404);
    }

    const device = await frida.getDevice(deviceId);
    const apps = await device
      .enumerateApplications({
        identifiers: [bundle],
        scope: frida.Scope.Full,
      })
      .catch(() => []);

    const app = apps.at(0);
    if (!app) {
      return c.json({ error: "application not found" }, 404);
    }

    const { icons } = app.parameters as {
      icons?: { format: string; image: Buffer }[];
    };

    if (icons && icons.length) {
      const ico = icons.find((i) => i.format === "png");
      if (ico && ico.image) {
        c.header("Content-Type", "image/png");
        return c.body(new Uint8Array(ico.image));
      }
    }

    return c.json({ error: "icon not found" }, 404);
  })
  .get("/device/:device/info", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    return c.json(await device.querySystemParameters());
  })
  .put("/devices/remote/:hostname", async (c) => {
    const hostname = c.req.param("hostname");
    await manager.addRemoteDevice(hostname);
    return c.body(null, 204);
  })
  .delete("/devices/remote/:hostname", async (c) => {
    const hostname = c.req.param("hostname");
    const deviceExists = await manager
      .getDeviceById(hostname, env.timeout)
      .then((dev) => dev.type === "remote")
      .catch(() => false);

    if (deviceExists) {
      const prefix = "socket@";
      const host = hostname.substring(prefix.length);
      await manager.removeRemoteDevice(host);
      return c.body(null, 204);
    } else {
      return c.json({ error: "remote device not found" }, 404);
    }
  });

app.route("/api", api);

export default app;
