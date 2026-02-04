import frida from "frida";
import { describe, it } from "node:test";
import assert from "node:assert";
import { agent } from "../lib/assets.ts";

describe("load agent", () => {
  ["fruity", "droid", "transport"].forEach((variant) => {
    it(`should load ${variant} agent source`, async () => {
      const source = await agent(variant);
      assert(typeof source === "string", "Agent source should be a string");
      assert(source.length > 0, "Agent source should not be empty");
    });
  });

  it("should spawn app", async () => {
    const deviceId = process.env.UDID;
    if (!deviceId) {
      console.warn("Skipping test: UDID environment variable not set");
      return;
    }

    const source = await agent("fruity");

    try {
      const dev = await frida.getUsbDevice();
      const pid = await dev.spawn("com.apple.mobilesafari", {
        env: { DISABLE_TWEAKS: "1" },
      });
      console.log("pid:", pid);
      const session = await dev.attach(pid);
      await dev.resume(pid);
      console.log("session", session);
      const script = await session.createScript(source);

      script.logHandler = (level, text) => {
        console.log(`[agent][${level}] ${text}`);
      };

      await script.load();
      console.log("interfaces:", await script.exports.interfaces());
      console.log("ok");

      await script.unload();
      await session.detach();

      await dev.kill(pid);
    } catch (ex) {
      console.error(ex);
      throw ex;
    }
  });
});
