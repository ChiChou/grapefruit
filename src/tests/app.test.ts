import { describe, it } from "node:test";
import assert from "node:assert";

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

    const r4 = await app.request(`/api/device/${udid}/processes`);
    const processes = (await r4.json()) as { name: string; pid: number }[];
    console.debug("processes", processes.slice(0, 10));
    assert(Array.isArray(processes), "Processes should be an array");
    if (processes.length > 0) {
      assert("name" in processes[0], "Process should have name");
      assert("pid" in processes[0], "Process should have pid");
    }
  });
});
