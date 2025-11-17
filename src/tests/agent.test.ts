import frida from "frida";
import { join } from "node:path";
import { promises as fs } from "node:fs";
import { describe, it } from "node:test";

describe("load agent", () => {
  it("should spawn app", async () => {
    const deviceId = process.env.UDID;
    if (!deviceId) {
      console.warn("Skipping test: UDID environment variable not set");
      return;
    }

    const script16 = join(
      import.meta.dirname,
      "..",
      "..",
      "agent",
      "dist",
      "fruity@16.js",
    );
    const source = await fs.readFile(script16, "utf8");

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
