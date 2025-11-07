import { type AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import { createServer } from "node:http";
import assert from "node:assert";

import frida from "frida";
import ioc from "socket.io-client";

import attach from "../ws.ts";

let server: ReturnType<typeof createServer>;

before(async () => {
  server = createServer();
  attach(server);
  return new Promise<void>((resolve) => server.listen(() => resolve()));
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("socket.io tests", () => {
  it("should notify clients on device change", async () => {
    const mgr = frida.getDeviceManager();

    await new Promise<void>((resolve, reject) => {
      const { port } = server.address() as AddressInfo;
      const socket = ioc(`http://127.0.0.1:${port}/devices`);
      const timeout = setTimeout(
        () => reject(new Error("test timed out")),
        1000,
      );

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
        reject(new Error(`Socket connection failed: ${err.message}`));
      });
    });
  });
});
