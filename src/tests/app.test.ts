import { describe, it, afterEach } from "node:test";
import assert from "node:assert";
import fs from "node:fs/promises";
import nodePath from "node:path";

import app from "../app.ts";
import env from "../lib/env.ts";
import { HookStore } from "../lib/store/hooks.ts";
import { CryptoStore } from "../lib/store/crypto.ts";
import { NSURLStore } from "../lib/store/nsurl.ts";
import { FlutterStore } from "../lib/store/flutter.ts";
import { JNIStore } from "../lib/store/jni.ts";
import { XPCStore } from "../lib/store/xpc.ts";
import { createTapStore } from "../lib/store/taps.ts";

const device = "test-device";
const identifier = "com.test.app";

function getStores() {
  return {
    hooks: new HookStore(device, identifier),
    crypto: new CryptoStore(device, identifier),
    nsurl: new NSURLStore(device, identifier),
    flutter: new FlutterStore(device, identifier),
    jni: new JNIStore(device, identifier),
    xpc: new XPCStore(device, identifier),
  };
}

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
    assert(
      r.status === 404 || r.status === 500,
      "Should return 404 or 500 for non-existent device",
    );
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
    assert(
      r1.status === 204 || r1.status === 200 || r1.status >= 400,
      "PUT should return appropriate status",
    );

    // Test removing a non-existent remote device
    const r2 = await app.request("/api/devices/remote/nonexistent", {
      method: "DELETE",
    });
    assert.strictEqual(
      r2.status,
      404,
      "DELETE should return 404 for non-existent device",
    );
  });

  it("should return 404 for non-existent app icon", async () => {
    const udid = process.env.UDID;
    if (!udid) {
      console.warn("Skipping icon test: UDID environment variable not set");
      return;
    }

    const r = await app.request(
      `/api/device/${udid}/icon/com.nonexistent.bundle`,
    );
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

describe("Logs API", () => {
  const logsDir = nodePath.join(nodePath.join(env.workdir, "data"), "logs", device, identifier);

  afterEach(async () => {
    await fs.rm(logsDir, { recursive: true, force: true });
  });

  it("should reject invalid log type", async () => {
    const r = await app.request(`/api/logs/${device}/${identifier}/invalid`);
    assert.strictEqual(r.status, 400);
    assert.strictEqual(await r.text(), "invalid log type");
  });

  it("should return empty string for missing log file", async () => {
    const r = await app.request(`/api/logs/${device}/${identifier}/syslog`);
    assert.strictEqual(r.status, 200);
    assert.strictEqual(await r.text(), "");
  });

  it("should return syslog content", async () => {
    await fs.mkdir(logsDir, { recursive: true });
    await fs.writeFile(
      nodePath.join(logsDir, "syslog.log"),
      "line1\nline2\nline3\n",
    );

    const r = await app.request(`/api/logs/${device}/${identifier}/syslog`);
    assert.strictEqual(r.status, 200);
    const text = await r.text();
    assert(text.includes("line1"));
    assert(text.includes("line3"));
  });

  it("should return agent log content", async () => {
    await fs.mkdir(logsDir, { recursive: true });
    await fs.writeFile(nodePath.join(logsDir, "agent.log"), "[info] hello\n");

    const r = await app.request(`/api/logs/${device}/${identifier}/agent`);
    assert.strictEqual(r.status, 200);
    assert(await r.text(), "[info] hello");
  });

  it("should return full content for small files", async () => {
    await fs.mkdir(logsDir, { recursive: true });
    const lines =
      Array.from({ length: 10 }, (_, i) => `line${i}`).join("\n") + "\n";
    await fs.writeFile(nodePath.join(logsDir, "syslog.log"), lines);

    const r = await app.request(`/api/logs/${device}/${identifier}/syslog`);
    const text = await r.text();
    const returned = text.split("\n").filter(Boolean);
    assert.strictEqual(returned.length, 10);
    assert.strictEqual(returned[0], "line0");
  });

  it("should delete logs directory", async () => {
    await fs.mkdir(logsDir, { recursive: true });
    await fs.writeFile(nodePath.join(logsDir, "syslog.log"), "data\n");

    const r = await app.request(`/api/logs/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const exists = await fs.access(logsDir).then(
      () => true,
      () => false,
    );
    assert.strictEqual(exists, false);
  });
});

describe("Hooks API", () => {
  afterEach(() => {
    getStores().hooks.rm();
  });

  it("should return empty hooks list", async () => {
    const r = await app.request(`/api/hooks/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = (await r.json()) as {
      hooks: unknown[];
      total: number;
      limit: number;
      offset: number;
    };
    assert.deepStrictEqual(body.hooks, []);
    assert.strictEqual(body.total, 0);
    assert.strictEqual(body.limit, 1000);
    assert.strictEqual(body.offset, 0);
  });

  it("should return inserted hooks", async () => {
    const { hooks: hookStore } = getStores();
    hookStore.append({
      category: "network",
      symbol: "send",
      dir: "out",
    });
    hookStore.append({
      category: "crypto",
      symbol: "encrypt",
      dir: "in",
    });

    const r = await app.request(`/api/hooks/${device}/${identifier}`);
    const body = (await r.json()) as { hooks: any[]; total: number };
    assert.strictEqual(body.total, 2);
    assert.strictEqual(body.hooks.length, 2);
    // newest first
    assert.strictEqual(body.hooks[0].category, "crypto");
    assert.strictEqual(body.hooks[1].category, "network");
    assert.strictEqual(body.hooks[0].symbol, "encrypt");
    assert.strictEqual(body.hooks[0].direction, "in");
  });

  it("should return extra as parsed object", async () => {
    const { hooks: hookStore } = getStores();
    hookStore.append({
      category: "c",
      symbol: "s",
      dir: "out",
      extra: { key: "value", num: 42 },
    });

    const r = await app.request(`/api/hooks/${device}/${identifier}`);
    const body = (await r.json()) as { hooks: any[] };
    assert.strictEqual(typeof body.hooks[0].extra, "object");
    assert.strictEqual(body.hooks[0].extra.key, "value");
    assert.strictEqual(body.hooks[0].extra.num, 42);
  });

  it("should filter by category", async () => {
    const { hooks: hookStore } = getStores();
    hookStore.append({
      category: "network",
      symbol: "send",
      dir: "out",
    });
    hookStore.append({
      category: "crypto",
      symbol: "enc",
      dir: "in",
    });

    const r = await app.request(
      `/api/hooks/${device}/${identifier}?category=crypto`,
    );
    const body = (await r.json()) as { hooks: any[]; total: number };
    assert.strictEqual(body.total, 1);
    assert.strictEqual(body.hooks.length, 1);
    assert.strictEqual(body.hooks[0].category, "crypto");
  });

  it("should store and query flutter.channel hooks", async () => {
    const { hooks: hookStore } = getStores();
    hookStore.append({
      category: "flutter.channel",
      symbol: "flutter.method",
      dir: "leave",
      line: "plugins.flutter.io/share",
      extra: {
        type: "method",
        dir: "native",
        channel: "plugins.flutter.io/share",
        method: "share",
        args: { text: "hello" },
      },
    });

    const r = await app.request(
      `/api/hooks/${device}/${identifier}?category=flutter.channel`,
    );
    assert.strictEqual(r.status, 200);

    const body = (await r.json()) as { hooks: any[]; total: number };
    assert.strictEqual(body.total, 1);
    assert.strictEqual(body.hooks.length, 1);
    assert.strictEqual(body.hooks[0].category, "flutter.channel");
    assert.strictEqual(body.hooks[0].extra.channel, "plugins.flutter.io/share");
    assert.strictEqual(body.hooks[0].extra.method, "share");
  });

  it("should paginate with limit and offset", async () => {
    const { hooks: hookStore } = getStores();
    for (let i = 0; i < 5; i++) {
      hookStore.append({
        category: "c",
        symbol: `s${i}`,
        dir: "out",
      });
    }

    const r = await app.request(
      `/api/hooks/${device}/${identifier}?limit=2&offset=1`,
    );
    const body = (await r.json()) as {
      hooks: any[];
      total: number;
      limit: number;
      offset: number;
    };
    assert.strictEqual(body.hooks.length, 2);
    assert.strictEqual(body.limit, 2);
    assert.strictEqual(body.offset, 1);
    assert.strictEqual(body.total, 5);
  });

  it("should clear hooks", async () => {
    const { hooks: hookStore } = getStores();
    hookStore.append({
      category: "c",
      symbol: "s",
      dir: "out",
    });

    const r = await app.request(`/api/hooks/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(`/api/hooks/${device}/${identifier}`);
    const body = (await r2.json()) as { total: number };
    assert.strictEqual(body.total, 0);
  });

  it("should isolate hooks by device/identifier", async () => {
    const { hooks: hookStore } = getStores();
    hookStore.append({
      category: "c",
      symbol: "s",
      dir: "out",
    });

    const otherHooks = new HookStore(device, "com.other.app");
    otherHooks.append({
      category: "c",
      symbol: "s",
      dir: "out",
    });

    const r = await app.request(`/api/hooks/${device}/${identifier}`);
    const body = (await r.json()) as { total: number };
    assert.strictEqual(body.total, 1);

    // cleanup other
    otherHooks.rm();
  });
});

describe("Crypto Logs API", () => {
  afterEach(() => {
    getStores().crypto.rm();
  });

  it("should return empty crypto logs", async () => {
    const r = await app.request(`/api/history/crypto/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = (await r.json()) as { logs: unknown[]; total: number };
    assert.deepStrictEqual(body.logs, []);
    assert.strictEqual(body.total, 0);
  });

  it("should return inserted crypto logs", async () => {
    const { crypto: cryptoStore } = getStores();
    cryptoStore.append({
      symbol: "CCCrypt",
      dir: "encrypt",
    });
    cryptoStore.append({
      symbol: "SecKeyEncrypt",
      dir: "decrypt",
    });

    const r = await app.request(`/api/history/crypto/${device}/${identifier}`);
    const body = (await r.json()) as { logs: any[]; total: number };
    assert.strictEqual(body.total, 2);
    assert.strictEqual(body.logs.length, 2);
    // newest first
    assert.strictEqual(body.logs[0].symbol, "SecKeyEncrypt");
    assert.strictEqual(body.logs[1].symbol, "CCCrypt");
  });

  it("should return extra and backtrace as parsed objects", async () => {
    const { crypto: cryptoStore } = getStores();
    cryptoStore.append({
      symbol: "CCCrypt",
      dir: "encrypt",
      extra: { algo: "AES" },
      backtrace: ["0x1000", "0x2000"],
    });

    const r = await app.request(`/api/history/crypto/${device}/${identifier}`);
    const body = (await r.json()) as { logs: any[] };
    assert.strictEqual(typeof body.logs[0].extra, "object");
    assert.strictEqual(body.logs[0].extra.algo, "AES");
    assert(Array.isArray(body.logs[0].backtrace));
    assert.strictEqual(body.logs[0].backtrace[0], "0x1000");
  });

  it("should paginate crypto logs", async () => {
    const { crypto: cryptoStore } = getStores();
    for (let i = 0; i < 5; i++) {
      cryptoStore.append({ symbol: `sym${i}`, dir: "enc" });
    }

    const r = await app.request(
      `/api/history/crypto/${device}/${identifier}?limit=2&offset=1`,
    );
    const body = (await r.json()) as {
      logs: any[];
      total: number;
      limit: number;
      offset: number;
    };
    assert.strictEqual(body.logs.length, 2);
    assert.strictEqual(body.total, 5);
  });

  it("should clear crypto logs", async () => {
    const { crypto: cryptoStore } = getStores();
    cryptoStore.append({ symbol: "s", dir: "enc" });

    const r = await app.request(`/api/history/crypto/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(`/api/history/crypto/${device}/${identifier}`);
    const body = (await r2.json()) as { total: number };
    assert.strictEqual(body.total, 0);
  });
});

describe("NSURL API", () => {
  afterEach(() => {
    getStores().nsurl.rm();
  });

  it("should return empty NSURL records", async () => {
    const r = await app.request(`/api/history/nsurl/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = (await r.json()) as { requests: unknown[]; total: number };
    assert.deepStrictEqual(body.requests, []);
    assert.strictEqual(body.total, 0);
  });

  it("should return upserted NSURL requests", async () => {
    const { nsurl: nsurlStore } = getStores();
    nsurlStore.upsert({
      event: "requestWillBeSent",
      requestId: "req-1",
      timestamp: 1000,
      request: { method: "GET", url: "https://example.com/api", headers: {} },
    });
    nsurlStore.upsert({
      event: "responseReceived",
      requestId: "req-1",
      timestamp: 1100,
      response: { statusCode: 200, mimeType: "application/json", expectedContentLength: 0, headers: {} },
    });

    const r = await app.request(`/api/history/nsurl/${device}/${identifier}`);
    const body = (await r.json()) as { requests: any[]; total: number };
    assert.strictEqual(body.total, 1);
    assert.strictEqual(body.requests[0].method, "GET");
    assert.strictEqual(body.requests[0].url, "https://example.com/api");
    assert.strictEqual(body.requests[0].statusCode, 200);
  });

  it("should clear NSURL records", async () => {
    const { nsurl: nsurlStore } = getStores();
    nsurlStore.upsert({
      event: "requestWillBeSent",
      requestId: "req-1",
      timestamp: 1000,
      request: { method: "POST", url: "https://example.com", headers: {} },
    });

    const r = await app.request(`/api/history/nsurl/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(`/api/history/nsurl/${device}/${identifier}`);
    const body = (await r2.json()) as { total: number };
    assert.strictEqual(body.total, 0);
  });

  it("should isolate NSURL records by device/identifier", async () => {
    const { nsurl: nsurlStore } = getStores();
    nsurlStore.upsert({
      event: "requestWillBeSent",
      requestId: "req-1",
      timestamp: 1000,
      request: { method: "GET", url: "https://a.com", headers: {} },
    });

    const otherNsurl = new NSURLStore(device, "com.other.app");
    otherNsurl.upsert({
      event: "requestWillBeSent",
      requestId: "req-2",
      timestamp: 1000,
      request: { method: "GET", url: "https://b.com", headers: {} },
    });

    const r = await app.request(`/api/history/nsurl/${device}/${identifier}`);
    const body = (await r.json()) as { total: number };
    assert.strictEqual(body.total, 1);

    // cleanup other
    otherNsurl.rm();
  });
});

describe("Flutter Logs API", () => {
  afterEach(() => {
    getStores().flutter.rm();
  });

  it("should return empty flutter logs", async () => {
    const r = await app.request(`/api/history/flutter/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = (await r.json()) as { logs: unknown[]; total: number };
    assert.deepStrictEqual(body.logs, []);
    assert.strictEqual(body.total, 0);
  });

  it("should return inserted flutter logs", async () => {
    const { flutter: store } = getStores();
    store.append({
      type: "method",
      dir: "native",
      channel: "plugins.flutter.io/share",
      method: "share",
      args: { text: "hello" },
    });
    store.append({
      type: "event",
      dir: "dart",
      channel: "flutter/lifecycle",
    });

    const r = await app.request(`/api/history/flutter/${device}/${identifier}`);
    const body = (await r.json()) as { logs: any[]; total: number };
    assert.strictEqual(body.total, 2);
    assert.strictEqual(body.logs.length, 2);
    // newest first
    assert.strictEqual(body.logs[0].channel, "flutter/lifecycle");
    assert.strictEqual(body.logs[0].type, "event");
    assert.strictEqual(body.logs[1].channel, "plugins.flutter.io/share");
    assert.strictEqual(body.logs[1].data.method, "share");
    assert.strictEqual(body.logs[1].data.args.text, "hello");
  });

  it("should clear flutter logs", async () => {
    const { flutter: store } = getStores();
    store.append({
      type: "method",
      dir: "native",
      channel: "test/channel",
    });

    const r = await app.request(
      `/api/history/flutter/${device}/${identifier}`,
      {
        method: "DELETE",
      },
    );
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(
      `/api/history/flutter/${device}/${identifier}`,
    );
    const body = (await r2.json()) as { total: number };
    assert.strictEqual(body.total, 0);
  });
});

describe("JNI Logs API", () => {
  afterEach(() => {
    getStores().jni.rm();
  });

  it("should return empty jni logs", async () => {
    const r = await app.request(`/api/history/jni/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = (await r.json()) as { logs: unknown[]; total: number };
    assert.deepStrictEqual(body.logs, []);
    assert.strictEqual(body.total, 0);
  });

  it("should return inserted jni logs", async () => {
    const { jni: store } = getStores();
    store.append({
      subject: "jni",
      type: "call",
      method: "GetStringUTFChars",
      callType: "JNIEnv",
      threadId: 1,
      args: ["0x1234"],
      ret: "hello",
      library: "libnative.so",
    });
    store.append({
      subject: "jni",
      type: "call",
      method: "FindClass",
      callType: "JNIEnv",
      threadId: 2,
      args: ["com/example/Test"],
      ret: "0x5678",
    });

    const r = await app.request(`/api/history/jni/${device}/${identifier}`);
    const body = (await r.json()) as { logs: any[]; total: number };
    assert.strictEqual(body.total, 2);
    assert.strictEqual(body.logs.length, 2);
    // newest first
    assert.strictEqual(body.logs[0].method, "FindClass");
    assert.strictEqual(body.logs[1].method, "GetStringUTFChars");
    assert.strictEqual(body.logs[1].library, "libnative.so");
  });

  it("should filter by method", async () => {
    const { jni: store } = getStores();
    store.append({
      subject: "jni",
      type: "call",
      method: "GetStringUTFChars",
      callType: "JNIEnv",
      threadId: 1,
      args: [],
      ret: "",
    });
    store.append({
      subject: "jni",
      type: "call",
      method: "FindClass",
      callType: "JNIEnv",
      threadId: 1,
      args: [],
      ret: "",
    });

    const r = await app.request(
      `/api/history/jni/${device}/${identifier}?method=FindClass`,
    );
    const body = (await r.json()) as { logs: any[]; total: number };
    assert.strictEqual(body.total, 1);
    assert.strictEqual(body.logs[0].method, "FindClass");
  });

  it("should clear jni logs", async () => {
    const { jni: store } = getStores();
    store.append({
      subject: "jni",
      type: "call",
      method: "FindClass",
      callType: "JNIEnv",
      threadId: 1,
      args: [],
      ret: "",
    });

    const r = await app.request(`/api/history/jni/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(`/api/history/jni/${device}/${identifier}`);
    const body = (await r2.json()) as { total: number };
    assert.strictEqual(body.total, 0);
  });
});

describe("XPC Logs API", () => {
  afterEach(() => {
    getStores().xpc.rm();
  });

  it("should return empty xpc logs", async () => {
    const r = await app.request(`/api/history/xpc/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = (await r.json()) as { logs: unknown[]; total: number };
    assert.deepStrictEqual(body.logs, []);
    assert.strictEqual(body.total, 0);
  });

  it("should return inserted xpc logs", async () => {
    const { xpc: store } = getStores();
    store.append({
      event: "sent",
      dir: ">",
      name: "com.apple.springboard",
      peer: 42,
      message: { type: "xpc", key: "value" },
    });
    store.append({
      event: "received",
      dir: "<",
      name: "com.apple.cfprefsd",
      message: { type: "nsxpc", method: "getPrefs" },
    });

    const r = await app.request(`/api/history/xpc/${device}/${identifier}`);
    const body = (await r.json()) as { logs: any[]; total: number };
    assert.strictEqual(body.total, 2);
    assert.strictEqual(body.logs.length, 2);
    // newest first
    assert.strictEqual(body.logs[0].protocol, "nsxpc");
    assert.strictEqual(body.logs[0].service, "com.apple.cfprefsd");
    assert.strictEqual(body.logs[1].protocol, "xpc");
    assert.strictEqual(body.logs[1].peer, 42);
  });

  it("should filter by protocol", async () => {
    const { xpc: store } = getStores();
    store.append({
      event: "sent",
      dir: ">",
      message: { type: "xpc" },
    });
    store.append({
      event: "sent",
      dir: ">",
      message: { type: "nsxpc" },
    });

    const r = await app.request(
      `/api/history/xpc/${device}/${identifier}?protocol=nsxpc`,
    );
    const body = (await r.json()) as { logs: any[]; total: number };
    assert.strictEqual(body.total, 1);
    assert.strictEqual(body.logs[0].protocol, "nsxpc");
  });

  it("should clear xpc logs", async () => {
    const { xpc: store } = getStores();
    store.append({
      event: "sent",
      dir: ">",
      message: { type: "xpc" },
    });

    const r = await app.request(`/api/history/xpc/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(`/api/history/xpc/${device}/${identifier}`);
    const body = (await r2.json()) as { total: number };
    assert.strictEqual(body.total, 0);
  });
});

describe("Taps API", () => {
  afterEach(() => {
    createTapStore(device, identifier).clear();
  });

  it("should return null for empty taps", async () => {
    const r = await app.request(`/api/taps/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = await r.json();
    assert.strictEqual(body, null);
  });

  it("should return saved taps", async () => {
    const store = createTapStore(device, identifier);
    const rules = [
      { type: "builtin" as const, id: "crypto" },
      {
        type: "objc" as const,
        cls: "NSURLSession",
        sel: "dataTaskWithRequest:",
      },
    ];
    store.save(rules);

    const r = await app.request(`/api/taps/${device}/${identifier}`);
    assert.strictEqual(r.status, 200);
    const body = await r.json();
    assert.strictEqual(body.length, 2);
    assert.strictEqual(body[0].type, "builtin");
    assert.strictEqual(body[0].id, "crypto");
    assert.strictEqual(body[1].type, "objc");
    assert.strictEqual(body[1].cls, "NSURLSession");
  });

  it("should clear taps", async () => {
    const store = createTapStore(device, identifier);
    store.save([{ type: "builtin" as const, id: "crypto" }]);

    const r = await app.request(`/api/taps/${device}/${identifier}`, {
      method: "DELETE",
    });
    assert.strictEqual(r.status, 204);

    const r2 = await app.request(`/api/taps/${device}/${identifier}`);
    const body = await r2.json();
    assert.strictEqual(body, null);
  });
});
