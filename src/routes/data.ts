import { Hono } from "hono";

import fs from "node:fs/promises";
import { createReadStream } from "node:fs";
import { Readable } from "node:stream";
import nodePath from "node:path";

import paths from "../lib/paths.ts";
import { HookStore } from "../lib/store/hooks.ts";
import { CryptoStore } from "../lib/store/crypto.ts";
import { NSURLStore } from "../lib/store/nsurl.ts";
import { FlutterStore } from "../lib/store/flutter.ts";
import { JNIStore } from "../lib/store/jni.ts";
import { XPCStore } from "../lib/store/xpc.ts";
import { createTapStore } from "../lib/store/taps.ts";
import { toHAR } from "../lib/har.ts";
const LOG_TAIL_BYTES = 1024 * 1024; // 1MB

interface LogStore<TRecord> {
  query(options: Record<string, unknown>, defaultLimit: number): TRecord[];
  count(filterValues?: Record<string, unknown>): number;
  rm(): void;
}

/**
 * Factory to create GET + DELETE route pair for a DB-backed log store.
 */
function createHistoryRoutes<TRecord>(config: {
  path: string;
  createStore: (deviceId: string, identifier: string) => LogStore<TRecord>;
  responseKey: string;
  defaultLimit: number;
  mapRecord: (record: TRecord) => unknown;
  extraQueryParams?: string[];
}) {
  const app = new Hono();

  app.get(`/${config.path}/:device/:identifier`, (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || String(config.defaultLimit), 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);
    const since = c.req.query("since");

    const extraParams: Record<string, string | undefined> = {};
    for (const param of config.extraQueryParams ?? []) {
      extraParams[param] = c.req.query(param);
    }

    try {
      const store = config.createStore(deviceId, identifier);

      const records = store.query({ limit, offset, since, ...extraParams }, config.defaultLimit);
      const mapped = records.map(config.mapRecord);

      // Build count filter from extra params
      const countFilter: Record<string, unknown> = {};
      for (const param of config.extraQueryParams ?? []) {
        if (extraParams[param]) countFilter[param] = extraParams[param];
      }
      const total = store.count(
        Object.keys(countFilter).length > 0 ? countFilter : undefined,
      );

      return c.json({ [config.responseKey]: mapped, total, limit, offset });
    } catch (e) {
      console.error(`Failed to query ${config.path}:`, e);
      return c.json({ [config.responseKey]: [], total: 0, limit, offset });
    }
  });

  app.delete(`/${config.path}/:device/:identifier`, (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      config.createStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error(`Failed to clear ${config.path}:`, e);
      return c.text(`Failed to clear ${config.path}`, 500);
    }
  });

  return app;
}

const hookRoutes = createHistoryRoutes({
  path: "hooks",
  createStore: (d, i) => new HookStore(d, i),
  responseKey: "hooks",
  defaultLimit: 1000,
  extraQueryParams: ["category"],
  mapRecord: (r) => ({
    id: r.id,
    timestamp: r.timestamp,
    category: r.category,
    symbol: r.symbol,
    direction: r.direction,
    line: r.line,
    extra: r.extra ? JSON.parse(r.extra) : undefined,
    createdAt: r.createdAt,
  }),
});

const cryptoRoutes = createHistoryRoutes({
  path: "history/crypto",
  createStore: (d, i) => new CryptoStore(d, i),
  responseKey: "logs",
  defaultLimit: 1000,
  mapRecord: (r) => ({
    id: r.id,
    timestamp: r.timestamp,
    symbol: r.symbol,
    direction: r.direction,
    line: r.line,
    extra: r.extra ? JSON.parse(r.extra) : undefined,
    backtrace: r.backtrace ? JSON.parse(r.backtrace) : undefined,
    data: r.data ? Buffer.from(r.data).toString("base64") : undefined,
    createdAt: r.createdAt,
  }),
});

const jniRoutes = createHistoryRoutes({
  path: "history/jni",
  createStore: (d, i) => new JNIStore(d, i),
  responseKey: "logs",
  defaultLimit: 5000,
  extraQueryParams: ["method"],
  mapRecord: (r) => ({
    id: r.id,
    timestamp: r.timestamp,
    type: r.type,
    method: r.method,
    callType: r.callType,
    threadId: r.threadId,
    args: r.args ? JSON.parse(r.args) : undefined,
    ret: r.ret,
    backtrace: r.backtrace ? JSON.parse(r.backtrace) : undefined,
    library: r.library,
    createdAt: r.createdAt,
  }),
});

const flutterRoutes = createHistoryRoutes({
  path: "history/flutter",
  createStore: (d, i) => new FlutterStore(d, i),
  responseKey: "logs",
  defaultLimit: 5000,
  mapRecord: (r) => ({
    id: r.id,
    timestamp: r.timestamp,
    type: r.type,
    direction: r.direction,
    channel: r.channel,
    data: r.data ? JSON.parse(r.data) : undefined,
    createdAt: r.createdAt,
  }),
});

const xpcRoutes = createHistoryRoutes({
  path: "history/xpc",
  createStore: (d, i) => new XPCStore(d, i),
  responseKey: "logs",
  defaultLimit: 5000,
  extraQueryParams: ["protocol"],
  mapRecord: (r) => ({
    id: r.id,
    timestamp: r.timestamp,
    protocol: r.protocol,
    event: r.event,
    direction: r.direction,
    service: r.service,
    peer: r.peer,
    message: r.message ? JSON.parse(r.message) : undefined,
    backtrace: r.backtrace ? JSON.parse(r.backtrace) : undefined,
    createdAt: r.createdAt,
  }),
});

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
  // DB-backed log stores
  .route("/", hookRoutes)
  // Legacy alias for hooks delete
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
  .route("/", cryptoRoutes)
  .route("/", jniRoutes)
  .route("/", flutterRoutes)
  // NSURL endpoints (not factored — different pattern)
  .get("/history/nsurl/:device/:identifier/har", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      const nsurlStore = new NSURLStore(deviceId, identifier);
      const requests = nsurlStore.query({ limit: 10000, offset: 0 });
      const har = toHAR(requests);

      c.header(
        "Content-Disposition",
        `attachment; filename="${identifier}.har"`,
      );
      return c.json(har);
    } catch (e) {
      console.error("Failed to export HAR:", e);
      return c.text("Failed to export HAR", 500);
    }
  })
  .get("/history/nsurl/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const limit = parseInt(c.req.query("limit") || "5000", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);

    try {
      const nsurlStore = new NSURLStore(deviceId, identifier);

      const requests = nsurlStore.query({ limit, offset });
      const total = nsurlStore.count();

      return c.json({ requests, total, limit, offset });
    } catch (e) {
      console.error("Failed to query NSURL records:", e);
      return c.json({ requests: [], total: 0, limit, offset });
    }
  })
  .delete("/history/nsurl/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      new NSURLStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear NSURL records:", e);
      return c.text("Failed to clear NSURL records", 500);
    }
  })
  .get("/history/nsurl/:device/:identifier/attachment/:requestId", async (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const requestId = c.req.param("requestId");

    try {
      const nsurlStore = new NSURLStore(deviceId, identifier);

      const attachment = nsurlStore.getAttachment(requestId);

      if (!attachment) {
        return c.text("No attachment found", 404);
      }

      const stat = await fs.stat(attachment.path).catch(() => null);
      if (!stat) {
        return c.text("Attachment file not found", 404);
      }

      c.header("Content-Type", attachment.mimeType || "application/octet-stream");
      c.header("Content-Length", stat.size.toString());
      return c.body(
        Readable.toWeb(
          createReadStream(attachment.path),
        ) as unknown as ReadableStream,
      );
    } catch (e) {
      console.error("Failed to serve attachment:", e);
      return c.text("Failed to serve attachment", 500);
    }
  })
  .route("/", xpcRoutes)
  // Taps snapshot endpoints
  .get("/taps/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    const store = createTapStore(deviceId, identifier);
    const snapshot = store.load();
    if (!snapshot) {
      return c.json(null);
    }
    return c.json(snapshot);
  })
  .delete("/taps/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    createTapStore(deviceId, identifier).clear();
    return c.body(null, 204);
  });

export default routes;
