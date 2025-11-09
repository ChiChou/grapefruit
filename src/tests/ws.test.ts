import { type AddressInfo } from "node:net";
import { afterEach, beforeEach, describe, it } from "node:test";
import { createServer } from "node:http";
import assert from "node:assert";

import frida from "frida";
import ioc from "socket.io-client";

import attach from "../ws.ts";

let server: ReturnType<typeof createServer>;

beforeEach(async () => {
  server = createServer();
  attach(server);
  return new Promise<void>((resolve) => server.listen(() => resolve()));
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("socket.io tests", () => {
  it("should notify clients on device change", async () => {
    const mgr = frida.getDeviceManager();

    await new Promise<void>((resolve, reject) => {
      const { port } = server.address() as AddressInfo;
      const socket = ioc(`http://127.0.0.1:${port}/devices`);
      const timeout = setTimeout(() => {
        socket.disconnect();
        reject(new Error("test timed out"));
      }, 1000);

      socket.once("change", () => {
        clearTimeout(timeout);
        resolve();
        console.debug("Received device change event");
        socket.disconnect();
      });

      socket.on("connect", () => {
        assert(socket.connected, "socket client works");
        mgr.addRemoteDevice("127.0.0.1");
      });

      socket.on("connect_error", (err) => {
        clearTimeout(timeout);
        reject(new Error(`Socket connection failed: ${err.message}`));
      });
    });
  });

  it("should run rpc tests", async () => {
    const deviceId = process.env.UDID;
    if (!deviceId) {
      console.warn("Skipping /session test: UDID environment variable not set");
      return;
    }

    await new Promise<void>((resolve, reject) => {
      const { port } = server.address() as AddressInfo;
      const query = new URLSearchParams({
        device: deviceId,
        bundle: "com.apple.mobilesafari",
      });
      const socket = ioc(
        `http://localhost:${port}/session?${query.toString()}`,
      );

      const timeout = setTimeout(() => {
        socket.disconnect();
        reject(new Error("test timed out"));
      }, 5000);

      socket.once("ready", () => {
        clearTimeout(timeout);
        console.debug("Session ready, connection established");
        socket.emit("rpc", "invalid");
        socket.emit("rpc", "fs", "ls", ["bundle"], (result: any) => {
          console.log("rpc result:", result);
          socket.disconnect();
          resolve();
        });
      });

      socket.on("connect_error", (err) => {
        clearTimeout(timeout);
        reject(new Error(`Socket connection failed: ${err.message}`));
      });

      socket.on("disconnect", (reason) => {
        if (reason === "io server disconnect") {
          clearTimeout(timeout);
          reject(
            new Error("Server disconnected the socket, likely due to an error"),
          );
        }
      });
    });
  });
});
