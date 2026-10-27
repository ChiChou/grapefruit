import { type AddressInfo } from "node:net";
import { createServer } from "node:http";
import assert from "node:assert/strict";
import { describe, it } from "node:test";

import frida from "frida";
import ioc from "socket.io-client";
import type { Server } from "socket.io";

import attach from "../ws.ts";

function createTestServer() {
  const server = createServer();
  const io = attach(server) as Server;
  return { server, io };
}

async function closeTestServer(io: Server) {
  await new Promise<void>((resolve) => io.close(() => resolve()));
}

describe("socket.io tests", () => {
  it(
    "should notify clients on device change",
    async () => {
      const { server, io } = createTestServer();
      await new Promise<void>((resolve) => server.listen(() => resolve()));

      const mgr = frida.getDeviceManager();
      const { port } = server.address() as AddressInfo;
      const socket = ioc(`http://localhost:${port}/devices`);

      try {
        await new Promise<void>((resolve, reject) => {
          const finish = (error?: Error) => {
            clearTimeout(timer);
            if (error) reject(error);
            else resolve();
          };
          const timer = setTimeout(() => finish(new Error("Timed out waiting for device change")), 3000);
          socket.once("connect_error", finish);
          socket.once("change", () => finish());
          socket.once("connect", () => {
            mgr.addRemoteDevice("127.0.0.1").catch(finish);
          });
        });
      } finally {
        socket.disconnect();
        await closeTestServer(io);
      }
    },
    { timeout: 5000 },
  );

  it(
    "should reject session with missing params",
    async () => {
      const { server, io } = createTestServer();
      await new Promise<void>((resolve) => server.listen(() => resolve()));

      const { port } = server.address() as AddressInfo;
      const socket = ioc(`http://localhost:${port}/session`, {
        query: { device: "fake" },
      });

      try {
        let receivedInvalid = false;

        socket.on("invalid", () => {
          receivedInvalid = true;
          socket.disconnect();
        });

        await new Promise((resolve) => setTimeout(resolve, 500));

        assert.equal(receivedInvalid, true);
      } finally {
        socket.disconnect();
        await closeTestServer(io);
      }
    },
    { timeout: 5000 },
  );

  it(
    "should run rpc tests",
    async () => {
      const deviceId = process.env.UDID;
      if (!deviceId) {
        console.warn(
          "Skipping /session test: UDID environment variable not set",
        );
        return;
      }

      const { server, io } = createTestServer();
      await new Promise<void>((resolve) => server.listen(() => resolve()));

      const { port } = server.address() as AddressInfo;
      const socket = ioc(`http://localhost:${port}/session`, {
        query: {
          device: deviceId,
          platform: "fruity",
          mode: "app",
          bundle: "com.apple.mobilesafari",
        },
      });

      try {
        let receivedReady = false;

        socket.on("ready", () => {
          receivedReady = true;
          socket.emit("rpc", "invalid");
          socket.emit(
            "rpc",
            "fs",
            "ls",
            ["bundle"],
            (err: Error | null, result: unknown) => {
              console.log("rpc result:", result);
              socket.disconnect();
            },
          );
        });

        // Wait for events
        await new Promise((resolve) => setTimeout(resolve, 8000));

        assert.equal(receivedReady, true);
      } finally {
        socket.disconnect();
        await closeTestServer(io);
      }
    },
    { timeout: 15000 },
  );
});
