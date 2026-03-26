import { createMiddleware } from "hono/factory";
import frida, { type Device } from "./xvii.ts";

export const device = createMiddleware<{
  Variables: {
    device: Device;
    bundle?: string;
  };
}>(async (c, next) => {
  const deviceId = c.req.param("device");
  if (!deviceId) {
    return c.json({ error: "device not found" }, 404);
  }

  c.set("device", await frida.getDevice(deviceId));
  await next();
});
