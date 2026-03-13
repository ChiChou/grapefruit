import { Hono } from "hono";
import { stream } from "hono/streaming";
import { Readable } from "node:stream";
import { create as createTransport } from "../lib/transport.ts";
import { getDeviceMiddleware } from "../lib/middleware.ts";

const routes = new Hono()
  .get("/apk-entry/:device/:pid", getDeviceMiddleware, async (c) => {
    const apkPath = c.req.query("apk");
    const entry = c.req.query("entry");
    if (typeof apkPath !== "string" || typeof entry !== "string")
      return c.text("invalid parameters", 400);

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    const transport = await createTransport(device, pid);
    const { script, controller } = transport;

    let size: number;
    try {
      size = await script.exports.zipLen(apkPath, entry);
    } catch (e) {
      console.error(e);
      await transport.close();
      return c.text("entry not found", 404);
    }

    const fileName = entry.split("/").pop() || "file";
    c.header("Content-Length", size.toString());
    c.header(
      "Content-Disposition",
      `attachment; filename="${fileName}"`,
    );

    return stream(c, async (streamer) => {
      await Promise.all([
        new Promise<void>((resolve) => {
          controller.events.on("stream", async (incomingStream: Readable) => {
            for await (const chunk of incomingStream) {
              await streamer.write(chunk);
            }
            await transport.close();
            resolve();
          });
        }),
        script.exports.pullZip(apkPath, entry),
      ]);
    });
  });

export default routes;
