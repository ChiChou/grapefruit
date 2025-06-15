import fs from "node:fs";
import http from "node:http";
import path from "node:path";

import Koa from "koa";
import bodyParser from "koa-bodyparser";
import json from "koa-json";
import Router from "koa-router";
import logger from "koa-logger";
import { Server } from "socket.io";
import frida from "frida";

import env from "../lib/env.ts";
import type { Device, Application } from "../../gui/src/schema.d.ts";

// Mock data
const mockDevices: Device[] = [
  {
    name: "Mock iPhone",
    id: "mock-iphone-id",
    type: "usb",
    removable: false,
  },
  {
    name: "Mock iPad",
    id: "mock-ipad-id",
    type: "usb",
    removable: false,
  },
  {
    name: "Mock Remote Device",
    id: "mock-remote-id",
    type: "remote",
    removable: true,
  },
];

const mockApps: Application[] = [
  {
    name: "App Store",
    identifier: "com.apple.AppStore",
    pid: 1001,
  },
  {
    name: "Safari",
    identifier: "com.apple.mobilesafari",
    pid: 1002,
  },
  {
    name: "Settings",
    identifier: "com.apple.Preferences",
    pid: 1003,
  },
  {
    name: "Maps",
    identifier: "com.apple.Maps",
    pid: 1004,
  },
];

const mockDeviceInfo: frida.SystemParameters = {
  os: {
    id: "ios",
    name: "iOS",
    version: "16.0",
    build: "20A362",
  },
  platform: "darwin",
  arch: "arm64",
  hardware: {
    product: "iPhone14,2",
    platform: "t8010",
    model: "J71bAP",
  },
  access: "full",
  name: "Mock Device",
  uuid: "mock-device-uuid",
};

// Set up Koa app
const app = new Koa();
const router = new Router({ prefix: "/api" });

// Middleware to simulate delay for network requests
async function delayMiddleware(ctx: Koa.Context, next: Koa.Next) {
  const delay = Math.random() * 300 + 100; // Random delay between 100-400ms
  await new Promise((resolve) => setTimeout(resolve, delay));
  await next();
}

router
  .get("/devices", async (ctx) => {
    ctx.body = mockDevices;
  })
  .get("/device/:device/apps", async (ctx) => {
    ctx.body = mockApps.filter(() => Math.random() > 0.25);
  })
  .get("/device/:device/icon/:bundle", async (ctx) => {
    const iconPath = path.join(import.meta.dirname, "..", "assets", "app.png");
    ctx.type = "image/png";
    ctx.body = fs.createReadStream(iconPath);
  })
  .get("/device/:device/info", async (ctx) => {
    ctx.body = mockDeviceInfo;
  });

// Set up Koa middleware
app.use(delayMiddleware);
app.use(logger());
app.use(json({ pretty: false, param: "pretty" }));
app.use(router.routes()).use(router.allowedMethods()).use(bodyParser());

const server = http.createServer(app.callback());
const io = new Server(server);

const devicesNamespace = io.of("/devices");

setInterval(() => {
  devicesNamespace.emit("changed");
}, 2000);

const sessionNamespace = io.of("/session");
sessionNamespace.on("connection", async (socket) => {
  const { device, bundle } = socket.handshake.query;
  console.log(
    `Mock session connected for device ${device} and bundle ${bundle}`,
  );

  socket.disconnect(true);
});

server.listen(env.port, env.host, () => {
  console.log(`Server running at http://${env.host}:${env.port}/`);
});
