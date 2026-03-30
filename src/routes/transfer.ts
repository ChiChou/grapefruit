import { Hono } from "hono";
import { stream } from "hono/streaming";
import { create as createTransport } from "../lib/transport.ts";
import * as middleware from "../lib/middleware.ts";

const routes = new Hono()
  .get("/download/:device/:pid", middleware.device, async (c) => {
    const path = c.req.query("path");
    if (typeof path !== "string") return c.text("invalid path", 400);

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    const transport = await createTransport(device, pid);
    const { script } = transport;

    let size: number;
    try {
      size = await script.exports.len(path);
    } catch (e) {
      console.error(e);
      return c.text("file not found", 404);
    }

    const rangeHeader = c.req.header("Range");
    if (rangeHeader) {
      const match = rangeHeader.match(/bytes=(\d+)-(\d*)/);
      if (!match) {
        await transport.close();
        return c.text("invalid range", 416);
      }

      const start = parseInt(match[1], 10);
      const end = match[2] ? parseInt(match[2], 10) : size - 1;
      if (start >= size || end >= size || start > end) {
        c.header("Content-Range", `bytes */${size}`);
        await transport.close();
        return c.text("range not satisfiable", 416);
      }

      c.status(206);
      c.header("Content-Range", `bytes ${start}-${end}/${size}`);
      c.header("Content-Length", (end - start + 1).toString());
      c.header("Accept-Ranges", "bytes");

      return stream(c, (streamer) =>
        new Promise<void>((resolve, reject) => {
          script.message.connect((message, data) => {
            if (message.type !== "send") return;
            const ev = message.payload as { event: string; message?: string };
            switch (ev.event) {
              case "info":
                script.post({ type: "ack" });
                break;
              case "data":
                if (data) streamer.write(new Uint8Array(data));
                script.post({ type: "ack" });
                break;
              case "end":
                resolve();
                break;
              case "error":
                reject(new Error(ev.message ?? "range read failed"));
                break;
            }
          });
          script.exports.pullRange(path, start, end).catch(reject);
        }).finally(() => transport.close()),
      );
    }

    c.header("Content-Length", size.toString());
    c.header("Accept-Ranges", "bytes");
    c.header(
      "Content-Disposition",
      `attachment; filename="${path.split("/").pop()}"`,
    );

    return stream(c, (streamer) =>
      transport.pipe(streamer, () => script.exports.pull(path)),
    );
  })
  .on(["HEAD", "GET"], "/dump/:device/:pid", middleware.device, async (c) => {
    const path = c.req.query("path");
    if (typeof path !== "string") return c.text("invalid path", 400);

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    const transport = await createTransport(device, pid);
    const { script } = transport;

    let size: number;
    try {
      size = await script.exports.len(path);
    } catch (e) {
      console.error(e);
      await transport.close();
      return c.text("file not found", 404);
    }

    c.header("Content-Length", size.toString());
    c.header(
      "Content-Disposition",
      `attachment; filename="${path.split("/").pop()}"`,
    );

    if (c.req.method === "HEAD") {
      await transport.close();
      return c.body(null);
    }

    return stream(c, (streamer) => {
      return new Promise<void>((resolve, reject) => {
        script.message.connect((message, data) => {
          if (message.type !== "send") return;
          const event = message.payload as { event: string; message?: string; size?: number };

          switch (event.event) {
            case "info":
              script.post({ type: "ack" });
              break;
            case "data":
              if (data) streamer.write(new Uint8Array(data));
              script.post({ type: "ack" });
              break;
            case "end":
              resolve();
              break;
            case "error":
              reject(new Error(event.message ?? "dump failed"));
              break;
          }
        });

        // no need to await this, the real resolve happens
        // in the message handler once the process is complete
        script.exports.dump(path).catch(reject);
      }).finally(() => transport.close());
    });
  })
  .get("/resource/:device/:pid", middleware.device, async (c) => {
    const type = c.req.query("type");
    const name = c.req.query("name");
    if (typeof type !== "string" || typeof name !== "string")
      return c.text("invalid params", 400);

    const device = c.get("device");
    const pid = parseInt(c.req.param("pid"), 10);
    const transport = await createTransport(device, pid);
    const { script, controller } = transport;

    let size: number;
    try {
      size = await script.exports.resourceLen(type, name);
    } catch (e) {
      console.error(e);
      await transport.close();
      return c.text("resource not found", 404);
    }

    c.header("Content-Length", size.toString());
    c.header(
      "Content-Disposition",
      `attachment; filename="${name}"`,
    );

    return stream(c, (streamer) =>
      transport.pipe(streamer, () => script.exports.pullResource(type, name)),
    );
  })
  .post("/upload/:device/:pid", middleware.device, async (c) => {
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
