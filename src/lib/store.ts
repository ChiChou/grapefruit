import path from "node:path";

import { eq, and, gt, desc, count } from "drizzle-orm";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import * as schema from "./schema.ts";
import { preferences, hooks, capturedRequests, cryptoLogs } from "./schema.ts";
import paths from "./paths.ts";
import { asset } from "./assets.ts";

const dbPath = path.join(paths.data, "data.db");
const migrationsFolder = await asset('drizzle');

// workaround to support both bun and node.js runtime
const db: BaseSQLiteDatabase<"sync", any, typeof schema> = await (async () => {
  if (typeof globalThis.Bun === "undefined") {
    const { default: Database } = (await import("better-sqlite3")) as any;
    const { drizzle } = await import("drizzle-orm/better-sqlite3");
    const { migrate } = await import("drizzle-orm/better-sqlite3/migrator");
    const db = drizzle(new Database(dbPath), { schema });
    migrate(db, { migrationsFolder });
    return db;
  }

  const { drizzle } = await import("drizzle-orm/bun-sqlite");
  const { migrate } = await import("drizzle-orm/bun-sqlite/migrator");
  const db = drizzle(dbPath, { schema });
  migrate(db, { migrationsFolder });
  return db;
})();

// Preferences

export function setPreference(key: string, value: any): void {
  db.insert(preferences)
    .values({ key, value: JSON.stringify(value) })
    .onConflictDoUpdate({
      target: preferences.key,
      set: { value: JSON.stringify(value) },
    })
    .run();
}

export function getPreference(key: string): any {
  const row = db
    .select({ value: preferences.value })
    .from(preferences)
    .where(eq(preferences.key, key))
    .get();
  if (row?.value) {
    return JSON.parse(row.value);
  }
  return null;
}

export function deletePreference(key: string): void {
  db.delete(preferences).where(eq(preferences.key, key)).run();
}

export function resetPreferences(): void {
  db.delete(preferences).run();
}

// Hook logs

export interface HookRecord {
  id: number;
  deviceId: string;
  identifier: string;
  timestamp: string;
  category: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra: string | null;
  createdAt: string;
}

/**
 * Insert a hook message into the database
 */
export function insertHookLog(
  deviceId: string,
  identifier: string,
  message: Record<string, unknown>,
): void {
  const extra = message.extra as Record<string, unknown> | undefined;
  db.insert(hooks)
    .values({
      deviceId,
      identifier,
      timestamp: new Date().toISOString(),
      category: (message.category as string) || "unknown",
      symbol: (message.symbol as string) || "unknown",
      direction: (message.dir as string) || "unknown",
      line: (message.line as string) || null,
      extra: extra ? JSON.stringify(extra) : null,
    })
    .run();
}

/**
 * Query hook records with optional filters
 */
export function queryHookLogs(
  deviceId: string,
  identifier: string,
  options: {
    limit?: number;
    offset?: number;
    category?: string;
    since?: string;
  } = {},
): HookRecord[] {
  const { limit = 1000, offset = 0, category, since } = options;

  const conditions = [
    eq(hooks.deviceId, deviceId),
    eq(hooks.identifier, identifier),
  ];

  if (category) {
    conditions.push(eq(hooks.category, category));
  }

  if (since) {
    conditions.push(gt(hooks.timestamp, since));
  }

  const rows = db
    .select()
    .from(hooks)
    .where(and(...conditions))
    .orderBy(desc(hooks.id))
    .limit(limit)
    .offset(offset)
    .all();

  return rows as HookRecord[];
}

/**
 * Get the total count of hook records
 */
export function countHookLogs(
  deviceId: string,
  identifier: string,
  category?: string,
): number {
  const conditions = [
    eq(hooks.deviceId, deviceId),
    eq(hooks.identifier, identifier),
  ];

  if (category) {
    conditions.push(eq(hooks.category, category));
  }

  const result = db
    .select({ count: count() })
    .from(hooks)
    .where(and(...conditions))
    .get();

  return result?.count ?? 0;
}

/**
 * Delete all hook records for a session
 */
export function deleteHookLogs(deviceId: string, identifier: string): void {
  db.delete(hooks)
    .where(and(eq(hooks.deviceId, deviceId), eq(hooks.identifier, identifier)))
    .run();
}

// Crypto logs

export interface CryptoRecord {
  id: number;
  deviceId: string;
  identifier: string;
  timestamp: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra: string | null;
  backtrace: string | null;
  data: Buffer | null;
  createdAt: string;
}

export function insertCryptoLog(
  deviceId: string,
  identifier: string,
  message: Record<string, unknown>,
  data?: Buffer | null,
): void {
  const extra = message.extra as Record<string, unknown> | undefined;
  const btrace = message.backtrace as string[] | undefined;
  db.insert(cryptoLogs)
    .values({
      deviceId,
      identifier,
      timestamp: new Date().toISOString(),
      symbol: (message.symbol as string) || "unknown",
      direction: (message.dir as string) || "unknown",
      line: (message.line as string) || null,
      extra: extra ? JSON.stringify(extra) : null,
      backtrace: btrace?.length ? JSON.stringify(btrace) : null,
      data: data ?? null,
    })
    .run();
}

export function queryCryptoLogs(
  deviceId: string,
  identifier: string,
  options: { limit?: number; offset?: number; since?: string } = {},
): CryptoRecord[] {
  const { limit = 1000, offset = 0, since } = options;

  const conditions = [
    eq(cryptoLogs.deviceId, deviceId),
    eq(cryptoLogs.identifier, identifier),
  ];

  if (since) {
    conditions.push(gt(cryptoLogs.timestamp, since));
  }

  const rows = db
    .select()
    .from(cryptoLogs)
    .where(and(...conditions))
    .orderBy(desc(cryptoLogs.id))
    .limit(limit)
    .offset(offset)
    .all();

  return rows as CryptoRecord[];
}

export function countCryptoLogs(
  deviceId: string,
  identifier: string,
): number {
  const result = db
    .select({ count: count() })
    .from(cryptoLogs)
    .where(
      and(
        eq(cryptoLogs.deviceId, deviceId),
        eq(cryptoLogs.identifier, identifier),
      ),
    )
    .get();

  return result?.count ?? 0;
}

export function deleteCryptoLogs(
  deviceId: string,
  identifier: string,
): void {
  db.delete(cryptoLogs)
    .where(
      and(
        eq(cryptoLogs.deviceId, deviceId),
        eq(cryptoLogs.identifier, identifier),
      ),
    )
    .run();
}

// Captured HTTP requests

interface WebSocketMessage {
  direction: "send" | "receive";
  messageType: "data" | "string";
  message?: string;
  dataLength?: number;
  error?: string;
  timestamp: number;
}

export interface CapturedRequest {
  id: string;
  method: string;
  url: string;
  statusCode?: number;
  mimeType?: string;
  size: number;
  startTime: number;
  endTime?: number;
  duration?: number;
  requestHeaders: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  responseBody?: string;
  error?: string;
  mechanism?: string;
  isWebSocket?: boolean;
  wsMessages?: WebSocketMessage[];
}

interface HttpNetworkEvent {
  event: string;
  requestId: string;
  timestamp: number;
  [key: string]: unknown;
}

function applyHttpEvent(req: CapturedRequest, event: HttpNetworkEvent): void {
  switch (event.event) {
    case "requestWillBeSent": {
      const r = event.request as
        | { method: string; url: string; headers: Record<string, string>; body?: string }
        | undefined;
      if (!r) break;
      req.method = r.method;
      req.url = r.url;
      req.requestHeaders = r.headers || {};
      req.requestBody = r.body;
      break;
    }
    case "responseReceived": {
      const r = event.response as
        | { url?: string; mimeType?: string; statusCode?: number; headers?: Record<string, string> }
        | undefined;
      if (!r) break;
      req.statusCode = r.statusCode;
      req.mimeType = r.mimeType;
      req.responseHeaders = r.headers;
      if (r.url && !req.url) req.url = r.url;
      break;
    }
    case "dataReceived": {
      try {
        req.size += Number(event.dataLength);
      } catch { /* ignore */ }
      break;
    }
    case "loadingFinished": {
      req.responseBody = event.responseBody as string | undefined;
      req.endTime = event.timestamp;
      req.duration = event.timestamp - req.startTime;
      break;
    }
    case "loadingFailed": {
      req.error = event.error as string | undefined;
      req.endTime = event.timestamp;
      req.duration = event.timestamp - req.startTime;
      break;
    }
    case "mechanism": {
      req.mechanism = event.mechanism as string | undefined;
      break;
    }
    case "webSocketSend":
    case "webSocketReceive": {
      req.isWebSocket = true;
      if (!req.method) req.method = "WS";
      if (!req.wsMessages) req.wsMessages = [];
      req.wsMessages.push({
        direction: event.event === "webSocketSend" ? "send" : "receive",
        messageType: (event.messageType as "data" | "string") ?? "data",
        message: event.message as string | undefined,
        dataLength: event.dataLength ? Number(event.dataLength) : undefined,
        error: event.error as string | undefined,
        timestamp: event.timestamp,
      });
      break;
    }
  }
}

export function upsertCapturedRequest(
  deviceId: string,
  identifier: string,
  event: Record<string, unknown>,
): void {
  const requestId = (event.requestId as string) || "unknown";
  const httpEvent = event as unknown as HttpNetworkEvent;

  const existing = db
    .select()
    .from(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
        eq(capturedRequests.requestId, requestId),
      ),
    )
    .get();

  let req: CapturedRequest;
  if (existing) {
    req = JSON.parse(existing.data);
  } else {
    req = {
      id: requestId,
      method: "",
      url: "",
      requestHeaders: {},
      size: 0,
      startTime: httpEvent.timestamp,
    };
  }

  applyHttpEvent(req, httpEvent);

  const now = new Date().toISOString();
  if (existing) {
    db.update(capturedRequests)
      .set({ data: JSON.stringify(req), updatedAt: now })
      .where(eq(capturedRequests.id, existing.id))
      .run();
  } else {
    db.insert(capturedRequests)
      .values({
        deviceId,
        identifier,
        requestId,
        data: JSON.stringify(req),
      })
      .run();
  }
}

export function queryCapturedRequests(
  deviceId: string,
  identifier: string,
  options: { limit?: number; offset?: number } = {},
): CapturedRequest[] {
  const { limit = 5000, offset = 0 } = options;

  const rows = db
    .select({ data: capturedRequests.data })
    .from(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
      ),
    )
    .orderBy(desc(capturedRequests.id))
    .limit(limit)
    .offset(offset)
    .all();

  return rows.map((r) => JSON.parse(r.data) as CapturedRequest);
}

export function countCapturedRequests(
  deviceId: string,
  identifier: string,
): number {
  const result = db
    .select({ count: count() })
    .from(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
      ),
    )
    .get();

  return result?.count ?? 0;
}

export function deleteCapturedRequests(
  deviceId: string,
  identifier: string,
): void {
  db.delete(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
      ),
    )
    .run();
}
