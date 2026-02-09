import RemoteStreamController from "frida-remote-stream";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";
import { serveStatic } from "@hono/node-server/serve-static";
import { stream } from "hono/streaming";
import { Readable } from "node:stream";
import fs from "node:fs/promises";
import nodePath from "node:path";

import getVersion from "./lib/version.ts";
import env from "./lib/env.ts";
import frida, { type Device } from "./lib/xvii.ts";
import paths from "./lib/paths.ts";

import {
  app as serializeApp,
  device as serializeDevice,
  process as serializeProcess,
} from "./lib/serializer.ts";
import { agent } from "./lib/assets.ts";
import {
  queryHookLogs,
  countHookLogs,
  deleteHookLogs,
} from "./lib/store.ts";

const manager = frida.getDeviceManager();
const app = new Hono();

app.use(logger());
app.use("/api/*", prettyJSON());

const api = app.basePath("/api");
const getDeviceMiddleware = createMiddleware<{
  Variables: {
    device: Device;
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

    return c.json({
      frida: await getVersion(env.frida === 16 ? "frida16" : "frida"),
      igf: version,
    });
  })
  .get("/devices", async (c) => {
    const skip = new Set(["local", "socket", "barebone"]);
    const devices = await frida.enumerateDevices();
    return c.json(
      devices.filter((dev) => !skip.has(dev.id)).map(serializeDevice),
    );
  })
  .get("/download/:device/:pid", getDeviceMiddleware, async (c) => {
    console.log("inside route");
    const path = c.req.query("path");
    if (typeof path !== "string") return c.text("invalid path", 400);

    // need upstream frida-fs to support { start, end } in fs.createReadStream
    if (c.req.header("Range")) {
      return c.text("range download not implemented", 501);
    }

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);

    const agentSource = await agent("transport");
    const session = await device.attach(pid);
    const script = await session.createScript(agentSource);
    await script.load();

    const controller = new RemoteStreamController();
    controller.events.on("send", ({ stanza, data }) => {
      script.post(
        {
          type: "+stream",
          payload: stanza,
        },
        data,
      );
    });

    script.message.connect((message, data) => {
      if (message.type === "send") {
        const stanza = message.payload as {
          payload: { [key: string]: any };
          name: string;
        };
        if (stanza.name === "+stream") {
          controller.receive({
            stanza: stanza.payload,
            data,
          });
        }
      }
    });

    let size: number;
    try {
      size = await script.exports.len(path);
    } catch (e) {
      console.error(e);
      return c.text("file not found", 404);
    }

    c.header("Content-Length", size.toString());
    c.header(
      "Content-Disposition",
      `attachment; filename="${path.split("/").pop()}"`,
    );

    return stream(c, async (streamer) => {
      await Promise.all([
        new Promise<void>((resolve) => {
          controller.events.on("stream", async (incomingStream: Readable) => {
            for await (const chunk of incomingStream) {
              await streamer.write(chunk);
            }
            await script.unload();
            await session.detach();
            resolve();
          });
        }),
        script.exports.pull(path),
      ]);
    });
  })
  .post("/upload/:device/:pid", getDeviceMiddleware, async (c) => {
    const formBody = await c.req.parseBody();
    const path = formBody["path"];
    if (typeof path !== "string") return c.text("invalid path", 400);

    console.log("file upload to", path);

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);

    const agentSource = await agent("transport");
    const session = await device.attach(pid);
    const script = await session.createScript(agentSource);
    await script.load();

    const controller = new RemoteStreamController();
    controller.events.on("send", ({ stanza, data }) => {
      script.post(
        {
          type: "+stream",
          payload: stanza,
        },
        data,
      );
    });

    script.message.connect((message, data) => {
      if (message.type === "send") {
        const stanza = message.payload as {
          payload: { [key: string]: any };
          name: string;
        };
        if (stanza.name === "+stream") {
          controller.receive({
            stanza: stanza.payload,
            data,
          });
        }
      }
    });

    const file = formBody["file"];
    if (!(file instanceof File)) return c.text("invalid request", 400);

    console.log("upload file", file.name, file.type, file.size);

    // Set up agent recv() handler before sending any stream messages
    await script.exports.push(path);

    await new Promise<void>((resolve, reject) => {
      const writable = controller.open(`${pid}:${path}`, {
        meta: { type: "data" },
      });

      writable.on("error", reject);
      writable.on("finish", () => resolve());

      const reader = file.stream().getReader();
      const pump = () => {
        reader.read().then(({ done, value }) => {
          if (done) {
            writable.end();
            return;
          }
          if (!writable.write(value)) {
            writable.once("drain", pump);
          } else {
            pump();
          }
        }, reject);
      };
      pump();
    });

    await script.unload();
    await session.detach();

    return c.text("upload complete");
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
    return c.json(await device.querySystemParameters());
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
  })
  .get("/logs/:device/:identifier/:type", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const type = c.req.param("type");

    if (type !== "syslog" && type !== "agent") {
      return c.text("invalid log type", 400);
    }

    const filename = type === "syslog" ? "syslog.log" : "agent.log";
    const logPath = nodePath.join(
      paths.data,
      "logs",
      deviceId,
      identifier,
      filename,
    );

    try {
      const limit = parseInt(c.req.query("limit") || "5000", 10);
      const content = await fs.readFile(logPath, "utf-8");
      const lines = content.split("\n").filter((line) => line.length > 0);
      return c.text(lines.slice(-limit).join("\n"));
    } catch {
      return c.text("");
    }
  })
  .delete("/logs/:device/:identifier", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const logsDir = nodePath.join(paths.data, "logs", deviceId, identifier);
    await fs.rm(logsDir, { recursive: true, force: true });

    return c.body(null, 204);
  })
  // Hook log endpoints
  .get("/hooks/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "1000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);
    const category = c.req.query("category");
    const since = c.req.query("since");

    try {
      const records = queryHookLogs(deviceId, identifier, {
        limit,
        offset,
        category,
        since,
      });

      const hooks = records.map((r) => ({
        id: r.id,
        timestamp: r.timestamp,
        category: r.category,
        symbol: r.symbol,
        direction: r.direction,
        payload: JSON.parse(r.payload),
        created_at: r.created_at,
      }));

      const total = countHookLogs(deviceId, identifier, category);

      return c.json({ hooks, total, limit, offset });
    } catch (e) {
      console.error("Failed to query hooks:", e);
      return c.json({ hooks: [], total: 0, limit, offset });
    }
  })
  .delete("/hooks/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      deleteHookLogs(deviceId, identifier);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear hooks:", e);
      return c.text("Failed to clear hooks", 500);
    }
  })
  .delete("/hooks/:device/:identifier/db", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      deleteHookLogs(deviceId, identifier);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to delete hooks:", e);
      return c.text("Failed to delete hooks", 500);
    }
  });

app.route("/api", api);

export default app;
