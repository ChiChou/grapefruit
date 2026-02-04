import RemoteStreamController from "frida-remote-stream";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { logger } from "hono/logger";
import { prettyJSON } from "hono/pretty-json";
import { stream } from "hono/streaming";
import { Readable } from "node:stream";

import getVersion from "./lib/version.ts";
import env from "./lib/env.ts";
import frida, { type Device } from "./lib/xvii.ts";

import {
  app as serializeApp,
  device as serializeDevice,
  process as serializeProcess,
} from "./lib/serializer.ts";
import { agent } from "./lib/assets.ts";

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

    await Promise.all([
      new Promise<void>(async (resolve) => {
        const writable = controller.open(`${pid}:${path}`, {
          meta: { type: "data" },
        });

        const reader = file.stream().getReader();
        if (!reader) {
          resolve();
          return;
        }

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          writable.write(value);
        }
        writable.end();
        resolve();
      }),
      script.exports.push(path),
    ]);

    return c.text("not properly implemented yet", 501);
    // return c.text("upload complete");
  })
  .get("/device/:device/apps", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    const apps = await device.enumerateApplications();
    return c.json(apps.map(serializeApp));
  })
  .get("/device/:device/processes", getDeviceMiddleware, async (c) => {
    const device = c.get("device");
    const processes = await device.enumerateProcesses();
    return c.json(processes.map(serializeProcess));
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
