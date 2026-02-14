import { Hono } from "hono";
import fs from "node:fs/promises";
import nodePath from "node:path";

import paths from "../lib/paths.ts";
import * as hookStore from "../lib/store/hooks.ts";
import * as cryptoStore from "../lib/store/crypto.ts";
import * as httpStore from "../lib/store/requests.ts";

const routes = new Hono()
  .get("/logs/:device/:identifier/:type", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const type = c.req.param("type");

    const validTypes = ["syslog", "agent"];
    if (!validTypes.includes(type)) {
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

    try {
      const limit = parseInt(c.req.query("limit") || "5000", 10);
      const content = await fs.readFile(logPath, "utf-8");
      const lines = content.split("\n").filter((line) => line.length > 0);
      return c.text(lines.slice(-limit).join("\n"));
    } catch {
      return c.text("");
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
      const records = hookStore.query(deviceId, identifier, {
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

      const total = hookStore.count(deviceId, identifier, category);

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
      hookStore.rm(deviceId, identifier);
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
      hookStore.rm(deviceId, identifier);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to delete hooks:", e);
      return c.text("Failed to delete hooks", 500);
    }
  })
  // Crypto log endpoints
  .get("/crypto-logs/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "1000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);
    const since = c.req.query("since");

    try {
      const records = cryptoStore.query(deviceId, identifier, {
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

      const total = cryptoStore.count(deviceId, identifier);

      return c.json({ logs, total, limit, offset });
    } catch (e) {
      console.error("Failed to query crypto logs:", e);
      return c.json({ logs: [], total: 0, limit, offset });
    }
  })
  .delete("/crypto-logs/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      cryptoStore.rm(deviceId, identifier);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear crypto logs:", e);
      return c.text("Failed to clear crypto logs", 500);
    }
  })
  // HTTP log endpoints
  .get("/http-logs/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "5000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);

    try {
      const requests = httpStore.query(deviceId, identifier, {
        limit,
        offset,
      });
      const total = httpStore.count(deviceId, identifier);

      return c.json({ requests, total, limit, offset });
    } catch (e) {
      console.error("Failed to query http logs:", e);
      return c.json({ requests: [], total: 0, limit, offset });
    }
  })
  .delete("/http-logs/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      httpStore.rm(deviceId, identifier);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear http logs:", e);
      return c.text("Failed to clear http logs", 500);
    }
  });

export default routes;
