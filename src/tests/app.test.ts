import { after, before, describe, it } from "node:test";
import assert from "node:assert";
// import type { ServerType } from "@hono/node-server";

// import frida from "frida";
// import io from "socket.io-client";
// import { serve } from "@hono/node-server";

import app from "../app.ts";

describe("API tests", () => {
  it("should start http server", async () => {
    const r0 = await app.request("/api/version");
    const version = await r0.json();
    console.debug("version", version);
    assert("frida" in version);
    assert("igf" in version);

    const r1 = await app.request("/api/devices");
    const devices = await r1.json();
    console.debug("devices", devices);
    assert(Array.isArray(devices), "Devices should be an array");

    const udid = process.env.UDID;
    if (typeof udid !== "string") {
      console.warn("!! UDID env not set, skipping devices related tests");
      return;
    }

    const r2 = await app.request(`/api/device/${udid}/info`);
    const deviceInfo = (await r2.json()) as object;
    console.debug("deviceInfo", deviceInfo);
    assert("name" in deviceInfo);
    assert("platform" in deviceInfo);
    assert("arch" in deviceInfo);

    const r3 = await app.request(`/api/device/${udid}/apps`);
    const apps = await r3.json();
    console.debug("apps", apps.slice(0, 10));
    assert(Array.isArray(apps), "Apps should be an array");
  });

  // it("should accept socket.io clients", async () => {
  //   const socket = io(prefix() + "/devices");
  //   await new Promise<void>((resolve, reject) => {
  //     const timeout = setTimeout(
  //       () => reject(new Error("test timed out")),
  //       5000,
  //     );

  //     socket.on("change", () => {
  //       clearTimeout(timeout);
  //       resolve();
  //       socket.disconnect();
  //     });

  //     socket.on("connect", () => {
  //       assert(socket.connected, "socket client works");
  //       frida.getDeviceManager().addRemoteDevice("127.0.0.1");
  //     });

  //     socket.on("connect_error", (err) => {
  //       reject(new Error(`Socket connection failed: ${err.message}`));
  //     });
  //   });
  // });
});
