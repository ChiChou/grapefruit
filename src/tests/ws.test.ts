import { type AddressInfo } from "node:net";
import { createServer } from "node:http";
import { describe, it, expect } from "bun:test";

import frida from "frida";
import ioc from "socket.io-client";
import type { Server } from "socket.io";

import attach from "../ws.ts";

function createTestServer() {
  const server = createServer();
  const io = attach(server) as Server;
  return { server, io };
}

async function closeTestServer(server: ReturnType<typeof createServer>, io: Server) {
  io.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

describe("socket.io tests", () => {
  it("should notify clients on device change", async () => {
    const { server, io } = createTestServer();
    await new Promise<void>((resolve) => server.listen(() => resolve()));
    
    const mgr = frida.getDeviceManager();
    const { port } = server.address() as AddressInfo;
    const socket = ioc(`http://127.0.0.1:${port}/devices`);

    try {
      let receivedChange = false;
      let connected = false;

      socket.on("change", () => {
        receivedChange = true;
        console.debug("Received device change event");
        socket.disconnect();
      });

      socket.on("connect", () => {
        connected = true;
        expect(socket.connected).toBe(true);
        mgr.addRemoteDevice("127.0.0.1");
      });

      // Wait for events
      await new Promise(resolve => setTimeout(resolve, 500));
      
      expect(connected).toBe(true);
      expect(receivedChange).toBe(true);
    } finally {
      socket.disconnect();
      await closeTestServer(server, io);
    }
  }, { timeout: 5000 });

  it("should run rpc tests", async () => {
    const deviceId = process.env.UDID;
    if (!deviceId) {
      console.warn("Skipping /session test: UDID environment variable not set");
      return;
    }

    const { server, io } = createTestServer();
    await new Promise<void>((resolve) => server.listen(() => resolve()));
    
    const { port } = server.address() as AddressInfo;
    const query = new URLSearchParams({
      device: deviceId,
      bundle: "com.apple.mobilesafari",
    });
    const socket = ioc(`http://localhost:${port}/session?${query.toString()}`);

    try {
      let receivedReady = false;

      socket.on("ready", () => {
        receivedReady = true;
        console.debug("Session ready, connection established");
        socket.emit("rpc", "invalid");
        socket.emit(
          "rpc",
          "fs",
          "ls",
          ["bundle"],
          (err: Error | null, result: any) => {
            console.log("rpc result:", result);
            socket.disconnect();
          },
        );
      });

      // Wait for events
      await new Promise(resolve => setTimeout(resolve, 8000));
      
      expect(receivedReady).toBe(true);
    } finally {
      socket.disconnect();
      await closeTestServer(server, io);
    }
  }, { timeout: 15000 });
});
