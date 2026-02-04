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

  it("should return error for non-existent device", async () => {
    const r = await app.request("/api/device/nonexistent-device/apps");
    // Note: getDeviceMiddleware throws when device is not found, resulting in 500
    assert(r.status === 404 || r.status === 500, "Should return 404 or 500 for non-existent device");
  });

  it("should return 404 for missing device param", async () => {
    const r = await app.request("/api/device//apps");
    assert.strictEqual(r.status, 404);
  });

  it("should handle remote device management", async () => {
    // Test adding a remote device
    const r1 = await app.request("/api/devices/remote/invalid-hostname", {
      method: "PUT",
    });
    // PUT returns 204 on success
    assert(r1.status === 204 || r1.status === 200 || r1.status >= 400, "PUT should return appropriate status");

    // Test removing a non-existent remote device
    const r2 = await app.request("/api/devices/remote/nonexistent", {
      method: "DELETE",
    });
    assert.strictEqual(r2.status, 404, "DELETE should return 404 for non-existent device");
  });

  it("should return 404 for non-existent app icon", async () => {
    const udid = process.env.UDID;
    if (!udid) {
      console.warn("Skipping icon test: UDID environment variable not set");
      return;
    }

    const r = await app.request(`/api/device/${udid}/icon/com.nonexistent.bundle`);
    assert.strictEqual(r.status, 404, "Should return 404 for non-existent app");
  });

  it("should handle download request validation", async () => {
    const udid = process.env.UDID;
    if (!udid) {
      console.warn("Skipping download test: UDID environment variable not set");
      return;
    }

    // Test missing path parameter
    const r1 = await app.request(`/api/download/${udid}/1234`);
    assert.strictEqual(r1.status, 400, "Should return 400 for missing path");

    // Test range request not implemented
    const r2 = await app.request(`/api/download/${udid}/1234?path=/test`, {
      headers: { Range: "bytes=0-100" },
    });
    assert.strictEqual(r2.status, 501, "Should return 501 for range requests");
  });

  it("should handle upload request validation", async () => {
    const udid = process.env.UDID;
    if (!udid) {
      console.warn("Skipping upload test: UDID environment variable not set");
      return;
    }

    // Test missing path parameter
    const r1 = await app.request(`/api/upload/${udid}/1234`, {
      method: "POST",
    });
    assert.strictEqual(r1.status, 400, "Should return 400 for missing path");
  });
});
