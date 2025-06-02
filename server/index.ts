import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import net from "node:net";

import frida from "frida";
import Koa from "koa";
import bodyParser from "koa-bodyparser";
import json from "koa-json";
import Router from "koa-router";
import logger from "koa-logger";
import { Server } from "socket.io";

import {
  app as serializeApp,
  device as serializeDevice,
} from "./lib/serializer.ts";
import env from "./lib/env.ts";
import { ispawn, sameOrigin } from "./lib/utils.ts";

interface RPCParam {
  method: string;
  args: any[];
}

const manager = frida.getDeviceManager();
const app = new Koa();
const router = new Router({ prefix: "/api" });

async function fetchDevice(ctx: Koa.Context, next: Koa.Next) {
  const deviceId = ctx.params.device;
  const device = await manager.getDeviceById(deviceId, 1000);
  if (!device) ctx.throw(404, "device not found");
  ctx.state.device = device;
  await next();
}

router
  .get("/devices", async (ctx) => {
    const skip = new Set(["local", "socket", "barebone"]);
    const devices = await manager.enumerateDevices();
    ctx.body = devices.filter((dev) => !skip.has(dev.id)).map(serializeDevice);
  })
  .get("/device/:device/apps", fetchDevice, async (ctx) => {
    const apps = await (
      ctx.state.device as frida.Device
    ).enumerateApplications();
    ctx.body = apps.map(serializeApp);
  })
  .get("/device/:device/icon/:bundle", fetchDevice, async (ctx) => {
    const apps = await (ctx.state.device as frida.Device)
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
  .get("/device/:device/info", async (ctx) => {
    const TIMEOUT = 1000;
    const id = ctx.params.device;
    const device = await manager.getDeviceById(id, TIMEOUT);
    ctx.body = await device.querySystemParameters();
  });

app.use(logger());
app.use(json({ pretty: false, param: "pretty" }));
app.use(router.routes()).use(router.allowedMethods()).use(bodyParser());

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
});

const server = http.createServer(app.callback());
const io = new Server(server, {
  allowRequest(req, cb) {
    const origin = req.headers.origin;
    if (typeof origin !== "string") {
      cb(null, false);
      return;
    }

    const url = new URL(origin);
    const { hostname } = url;
    if (env.dev) {
      cb(null, hostname === "localhost");
      return;
    }

    cb(null, sameOrigin(new URL(env.frontend), url));
  },
});

const devicesNamespace = io.of("/devices");
manager.changed.connect(() => {
  devicesNamespace.emit("changed");
});

const sessionNamespace = io.of("/session");
sessionNamespace.on("connection", async (socket) => {
  const { device, bundle } = socket.handshake.query;
  if (typeof device !== "string" || typeof bundle !== "string") {
    console.warn(
      `Invalid handshake query parameters: ${JSON.stringify(socket.handshake.query)}`,
    );
    socket.disconnect(true);
    return;
  }

  const TIMEOUT = 1000;
  const deviceInstance = await manager.getDeviceById(device, TIMEOUT);
  await ispawn(deviceInstance, bundle);
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

  socket
    .on("rpc", async (param: RPCParam) => {
      // todo
    })
    .on("disconnect", async () => {
      await session.detach();
    });
});

server.listen(env.port, env.host, () => {
  const addr = server.address() as net.AddressInfo;
  console.log(`Server is running on http://${addr.address}:${addr.port}`);
});
