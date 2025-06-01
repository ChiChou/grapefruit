import assert from "node:assert";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";

import frida from "frida";
import { fileURLToPath } from "node:url";

const TIMEOUT = 1000;

async function getDevice() {
  const deviceId = process.env.DEVICE_ID;
  if (deviceId) {
    return await frida.getDeviceManager().getDeviceById(deviceId, TIMEOUT);
  }
  return await frida.getUsbDevice();
}

async function getScriptSource(name: string) {
  const __dirname = path.dirname(fileURLToPath(import.meta.url));
  const scriptPath = path.join(__dirname, "..", "dist", name + ".js");
  return fs.promises.readFile(scriptPath, "utf8");
}

test("SpringBoard agent test", async (t) => {
  const src = await getScriptSource("springboard");
  assert(src.length, "agent script is empty");

  const device = await getDevice();
  const session = await device.attach("SpringBoard");
  assert(session, "Failed to attach to SpringBoard");

  const script = await session.createScript(src);
  assert(script, "Failed to create script");
  script.logHandler = (level, message) => {
    console.log(`Log from script [${level}]: ${message}`);
  };

  await script.load();
  const api = script.exports;

  assert.strictEqual(await api.locked(), false, "Screen must not be unlocked");
  assert(await api.open("com.apple.Preferences"));

  await script.unload();
  await session.detach();
});

test("iOS agent", async (t) => {
  const src = await getScriptSource("fruity");
  assert(src.length, "iOS agent script is empty");

  const device = await getDevice();

  async function getSafari(){
    const session = await device.attach("SpringBoard");
    const script = await session.createScript(await getScriptSource("springboard"));
    await script.load();
    const api = script.exports;
    assert(!await api.locked());
    assert(await api.open("com.apple.mobilesafari"));
    const pid = await api.pidOf("com.apple.mobilesafari");
    assert(pid > 0);

    await script.unload();
    await session.detach();

    return pid;
  }

  const pid = await getSafari();
  const session = await device.attach(pid);
  assert(session);
  const script = await session.createScript(src);
  assert(script);
  await script.load();
  await script.unload();
  await session.detach();
});