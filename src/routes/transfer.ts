import { Hono } from "hono";
import { stream } from "hono/streaming";
import { Readable } from "node:stream";
import { create as createTransport } from "../lib/transport.ts";
import { getDeviceMiddleware } from "../lib/middleware.ts";

const routes = new Hono()
  .get("/download/:device/:pid", getDeviceMiddleware, async (c) => {
    const path = c.req.query("path");
    if (typeof path !== "string") return c.text("invalid path", 400);

    // need upstream frida-fs to support { start, end } in fs.createReadStream
    if (c.req.header("Range")) {
      return c.text("range download not implemented", 501);
    }

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    const transport = await createTransport(device, pid);
    const { script, controller } = transport;

    let size: number;
    try {
      size = await script.exports.len(path);
    } catch (e) {
      console.error(e);
      return c.text("file not found", 404);
    }

    c.header("Content-Length", size.toString());
    c.header(
      "Content-Disposition",
      `attachment; filename="${path.split("/").pop()}"`,
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
        script.exports.pull(path),
      ]);
    });
  })
  .post("/upload/:device/:pid", getDeviceMiddleware, async (c) => {
    const formBody = await c.req.parseBody();
    const path = formBody["path"];
    if (typeof path !== "string") return c.text("invalid path", 400);

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    const transport = await createTransport(device, pid);
    const { script, controller } = transport;

    const file = formBody["file"];
    if (!(file instanceof File)) return c.text("invalid request", 400);

    // Set up agent recv() handler before sending any stream messages
    await script.exports.push(path);

    await new Promise<void>((resolve, reject) => {
      const writable = controller.open(`${pid}:${path}`, {
        meta: { type: "data" },
      });

      writable.on("error", reject);
      writable.on("finish", () => resolve());

      const reader = file.stream().getReader();
      const pump = () => {
        reader.read().then(({ done, value }) => {
          if (done) {
            writable.end();
            return;
          }
          if (!writable.write(value)) {
            writable.once("drain", pump);
          } else {
            pump();
          }
        }, reject);
      };
      pump();
    });

    await transport.close();

    return c.text("upload complete");
  });

export default routes;
