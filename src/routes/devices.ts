import { Hono } from "hono";
import frida from "../lib/xvii.ts";
import {
  app as serializeApp,
  device as serializeDevice,
  process as serializeProcess,
} from "../lib/serializer.ts";
import { getDeviceMiddleware } from "../lib/middleware.ts";
import env from "../lib/env.ts";

const manager = frida.getDeviceManager();

const routes = new Hono()
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
  .get("/device/:device/processes", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    const processes = await device.enumerateProcesses({
      scope: frida.Scope.Metadata,
    });
    // filter out launchd for safety
    return c.json(
      processes
        .filter((proc) => proc.pid !== 1 && proc.name !== "launchd")
        .map(serializeProcess),
    );
  })
  .get("/device/:device/icon/:bundle", async (c) => {
    const deviceId = c.req.param("device");
    const bundle = c.req.param("bundle");

    if (!deviceId) {
      return c.text("device not found", 404);
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
      return c.text("application not found", 404);
    }

    const { icons } = app.parameters as {
      icons?: { format: string; image: Buffer }[];
    };

    if (icons && icons.length) {
      const ico = icons.find((i) => i.format === "png");
      if (ico && ico.image) {
        c.header("Content-Type", "image/png");
        c.header("Cache-Control", "public, max-age=604800"); // 7 days
        return c.body(new Uint8Array(ico.image));
      }
    }

    return c.text("icon not found", 404);
  })
  .get("/device/:device/info", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    const params = await device.querySystemParameters();
    return c.text(
      // 17.8.2 returns 'api-level' as bigint, causing JSON.stringify to throw
      JSON.stringify(params, (_, value) =>
        typeof value === "bigint" ? Number(value) : value,
      ),
      200,
      { "Content-Type": "application/json" },
    );
  })
  .post("/device/:device/kill/:pid", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    if (isNaN(pid)) {
      return c.json({ error: "invalid pid" }, 400);
    }
    try {
      await device.kill(pid);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to kill process:", e);
      return c.json({ error: "failed to kill process" }, 500);
    }
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

export default routes;
