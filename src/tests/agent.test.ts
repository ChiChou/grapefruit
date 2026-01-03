import frida from "frida";
import { describe, it } from "node:test";
import { readAgent } from "../lib/utils.ts";

describe("load agent", () => {
  it("should spawn app", async () => {
    const deviceId = process.env.UDID;
    if (!deviceId) {
      console.warn("Skipping test: UDID environment variable not set");
      return;
    }

    const source = await readAgent("fruity");

    try {
      const dev = await frida.getUsbDevice();
      const pid = await dev.spawn("com.apple.mobilesafari", {
        env: { DISABLE_TWEAKS: "1" },
      });
      console.log(pid);
      const session = await dev.attach(pid);
      await dev.resume(pid);
      console.log(session);
      const script = await session.createScript(source);
      console.log(script);
      await script.load();
      console.log("ok");

      await script.unload();
      await session.detach();
    } catch (ex) {
      console.error(ex);
    }
  });
});
