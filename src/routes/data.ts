import { Hono } from "hono";

import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import nodePath from "node:path";

import paths from "../lib/paths.ts";
import { HookStore } from "../lib/store/hooks.ts";
import { CryptoStore } from "../lib/store/crypto.ts";
import { HttpStore } from "../lib/store/requests.ts";

const LOG_TAIL_BYTES = 1024 * 1024; // 1MB

const routes = new Hono()
  .get("/logs/:device/:identifier/:type", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const type = c.req.param("type");

    if (!["syslog", "agent"].includes(type)) {
      return c.text("invalid log type", 400);
    }

    const filename = `${type}.log`;
    const logPath = nodePath.join(
      paths.data,
      "logs",
      deviceId,
      identifier,
      filename,
    );

    const stat = await fs.stat(logPath).catch(() => null);
    if (!stat) return c.text("");

    const { size } = stat;

    if (c.req.query("download")) {
      c.header(
        "Content-Disposition",
        `attachment; filename="${identifier}-${filename}"`,
      );
      c.header("Content-Type", "text/plain");
      c.header("Content-Length", size.toString());
      return c.body(
        Readable.toWeb(createReadStream(logPath)) as unknown as ReadableStream,
      );
    }

    if (size <= LOG_TAIL_BYTES)
      return c.text(await fs.readFile(logPath, "utf-8"));

    const handle = await fs.open(logPath, "r");
    const buf = Buffer.alloc(LOG_TAIL_BYTES);

    try {
      await handle.read(buf, 0, LOG_TAIL_BYTES, size - LOG_TAIL_BYTES);
      const chunk = buf.toString("utf-8");
      const idx = chunk.indexOf("\n");
      return c.text(idx === -1 ? chunk : chunk.slice(idx + 1));
    } finally {
      await handle.close();
    }
  })
  .delete("/logs/:device/:identifier", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const logsDir = nodePath.join(paths.data, "logs", deviceId, identifier);
    await fs.rm(logsDir, { recursive: true, force: true });

    return c.body(null, 204);
  })
  // Hook log endpoints
  .get("/hooks/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "1000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);
    const category = c.req.query("category");
    const since = c.req.query("since");

    try {
      const hookStore = new HookStore(deviceId, identifier);

      const records = hookStore.query({
        limit,
        offset,
        category,
        since,
      });

      const hooks = records.map((r) => ({
        id: r.id,
        timestamp: r.timestamp,
        category: r.category,
        symbol: r.symbol,
        direction: r.direction,
        line: r.line,
        extra: r.extra ? JSON.parse(r.extra) : undefined,
        createdAt: r.createdAt,
      }));

      const total = hookStore.count(category);

      return c.json({ hooks, total, limit, offset });
    } catch (e) {
      console.error("Failed to query hooks:", e);
      return c.json({ hooks: [], total: 0, limit, offset });
    }
  })
  .delete("/hooks/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      new HookStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear hooks:", e);
      return c.text("Failed to clear hooks", 500);
    }
  })
  .delete("/hooks/:device/:identifier/db", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      new HookStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to delete hooks:", e);
      return c.text("Failed to delete hooks", 500);
    }
  })
  // Crypto log endpoints
  .get("/history/crypto/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "1000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);
    const since = c.req.query("since");

    try {
      const cryptoStore = new CryptoStore(deviceId, identifier);

      const records = cryptoStore.query({
        limit,
        offset,
        since,
      });

      const logs = records.map((r) => ({
        id: r.id,
        timestamp: r.timestamp,
        symbol: r.symbol,
        direction: r.direction,
        line: r.line,
        extra: r.extra ? JSON.parse(r.extra) : undefined,
        backtrace: r.backtrace ? JSON.parse(r.backtrace) : undefined,
        data: r.data ? Buffer.from(r.data).toString("base64") : undefined,
        createdAt: r.createdAt,
      }));

      const total = cryptoStore.count();

      return c.json({ logs, total, limit, offset });
    } catch (e) {
      console.error("Failed to query crypto logs:", e);
      return c.json({ logs: [], total: 0, limit, offset });
    }
  })
  .delete("/history/crypto/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      new CryptoStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear crypto logs:", e);
      return c.text("Failed to clear crypto logs", 500);
    }
  })
  // HTTP log endpoints
  .get("/history/http/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "5000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);

    try {
      const httpStore = new HttpStore(deviceId, identifier);

      const requests = httpStore.query({ limit, offset });
      const total = httpStore.count();

      return c.json({ requests, total, limit, offset });
    } catch (e) {
      console.error("Failed to query http logs:", e);
      return c.json({ requests: [], total: 0, limit, offset });
    }
  })
  .delete("/history/http/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      new HttpStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear http logs:", e);
      return c.text("Failed to clear http logs", 500);
    }
  })
  // HTTP attachment download
  .get("/history/http/:device/:identifier/attachment/:requestId", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const requestId = c.req.param("requestId");

    try {
      const httpStore = new HttpStore(deviceId, identifier);

      const attachmentPath = httpStore.getAttachmentPath(requestId);

      if (!attachmentPath) {
        return c.text("No attachment found", 404);
      }

      const stat = await fs.stat(attachmentPath).catch(() => null);
      if (!stat) {
        return c.text("Attachment file not found", 404);
      }

      c.header(
        "Content-Disposition",
        `attachment; filename="${requestId}"`,
      );
      c.header("Content-Type", "application/octet-stream");
      c.header("Content-Length", stat.size.toString());
      return c.body(
        Readable.toWeb(
          createReadStream(attachmentPath),
        ) as unknown as ReadableStream,
      );
    } catch (e) {
      console.error("Failed to serve attachment:", e);
      return c.text("Failed to serve attachment", 500);
    }
  });

export default routes;
