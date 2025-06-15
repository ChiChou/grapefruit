import fs from "node:fs";
import http from "node:http";
import path from "node:path";

import frida from "frida";
import Koa from "koa";
import bodyParser from "koa-bodyparser";
import json from "koa-json";
import logger from "koa-logger";
import Router from "koa-router";
import send from "koa-send";
import { Server, Socket } from "socket.io";

import env from "./lib/env.ts";
import {
  app as serializeApp,
  device as serializeDevice,
} from "./lib/serializer.ts";
import { ispawn, agent as readAgent } from "./lib/utils.ts";

interface RPCParam {
  method: string;
  args: any[];
}

interface DownloadRequest {
  path: string;
}

interface UploadRequest {
  destination: string;
  size: number;
}

const manager = frida.getDeviceManager();
const app = new Koa();
const router = new Router({ prefix: "/api" });

async function fetchDevice(ctx: Koa.Context, next: Koa.Next) {
  const deviceId = ctx.params.device;
  const device = await frida.getDevice(deviceId);
  if (!device) ctx.throw(404, "device not found");
  ctx.state.device = device;
  await next();
}

router
  .get("/devices", async (ctx) => {
    const skip = new Set(["local", "socket", "barebone"]);
    const devices = await frida.enumerateDevices();
    ctx.body = devices.filter((dev) => !skip.has(dev.id)).map(serializeDevice);
  })
  .get("/device/:device/apps", fetchDevice, async (ctx) => {
    const device = ctx.state.device as frida.Device;
    const apps = await device.enumerateApplications();
    ctx.body = apps.map(serializeApp);
  })
  .get("/device/:device/icon/:bundle", fetchDevice, async (ctx) => {
    const device = ctx.state.device as frida.Device;
    const apps = await device
      .enumerateApplications({
        identifiers: [ctx.params.bundle],
        scope: frida.Scope.Full,
      })
      .catch(() => []);

    ctx.type = "image/png";

    const app = apps.at(0);
    if (app) {
      const { icons } = app?.parameters as {
        icons?: { format: string; image: Buffer }[];
      };

      if (icons && icons.length) {
        const ico = icons.find((i) => i.format === "png");
        if (ico && ico.image) {
          ctx.body = ico.image;
          return;
        }
      }
    }

    const placeholder = path.join(import.meta.dirname, "assets", "app.png");
    ctx.body = fs.createReadStream(placeholder);
  })
  .get("/device/:device/info", fetchDevice, async (ctx) => {
    const device = ctx.state.device as frida.Device;
    ctx.body = await device.querySystemParameters();
  })
  .put("/devices/remote/:hostname", async (ctx) => {
    await manager.addRemoteDevice(ctx.params.hostname);
    ctx.status = 204;
  })
  .delete("/devices/remote/:hostname", async (ctx) => {
    const address = ctx.params.hostname;
    const device = await manager.getDeviceById(address, env.timeout);
    if (device) {
      await manager.removeRemoteDevice(address);
      ctx.status = 204;
    } else {
      ctx.throw(404, "remote device not found");
    }
  });

if (!env.dev) {
  app.use(async (ctx, next) => {
    const guiRoot = path.join(import.meta.dirname, "..", "gui", "dist");
    const opt = { root: guiRoot, maxage: 0, gzip: true };

    if (ctx.path.startsWith("/api") || ctx.path.startsWith("/socket.io")) {
      await next();
    } else if (ctx.path.match(/(^\/(css|fonts|js|img)\/|\.js(.map)?$)/)) {
      await send(ctx, ctx.path, opt);
    } else {
      await send(ctx, "/index.html", opt);
    }
  });
} else {
  router.get("/", async (ctx) => {
    ctx.body =
      "Server in development mode, please open frontend dev server in browser instead";
    ctx.status = 404;
  });
}

app.use(logger());
app.use(json({ pretty: false, param: "pretty" }));
app.use(router.routes()).use(router.allowedMethods()).use(bodyParser());

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

async function onConnection(socket: Socket) {
  const { device, bundle } = socket.handshake.query;
  if (typeof device !== "string" || typeof bundle !== "string") {
    console.warn(
      `Invalid handshake query parameters: ${JSON.stringify(socket.handshake.query)}`,
    );
    socket.disconnect(true);
    return;
  }

  const deviceInstance = await manager.getDeviceById(device, env.timeout);
  if (!deviceInstance) {
    console.warn(`Device not found: ${device}`);
    socket.disconnect(true);
    return;
  }

  try {
    await ispawn(deviceInstance, bundle);
  } catch (error) {
    console.error(
      `Failed to spawn application ${bundle} on device ${device}:`,
      error,
    );
    socket.disconnect(true);
    return;
  }

  const apps = await deviceInstance.enumerateApplications({
    identifiers: [bundle],
    scope: frida.Scope.Full,
  });

  if (apps.length === 0) {
    console.warn(`No application found for bundle: ${bundle}`);
    socket.disconnect(true);
    return;
  }

  const { pid } = apps.at(0) as frida.Application;
  const session = await deviceInstance.attach(pid);
  const script = await session.createScript(await readAgent("fruity"));

  socket
    .on("download", async (param: DownloadRequest) => {
      // todo:
    })
    .on("rpc", async (param: RPCParam) => {
      // todo:
    })
    .on("disconnect", async () => {
      await script.unload();
      await session.detach();
    });

  await script.load();
  socket.emit("ready");
}

const server = http.createServer(app.callback());
const io = new Server(server);

function onDeviceChange() {
  console.log("Device manager changed, notifying clients");
  io.of("/devices").emit("change");
}

server
  .on("listening", () => manager.changed.connect(onDeviceChange))
  .on("close", () => manager.changed.disconnect(onDeviceChange));

io.of("/devices").on("connection", (socket: Socket) => {});
io.of("/session").on("connection", onConnection);

export default server;
