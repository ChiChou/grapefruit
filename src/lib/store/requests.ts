import { randomUUID } from "node:crypto";
import fs from "node:fs";
import nodePath from "node:path";
import { eq, and, desc, count as countFn } from "drizzle-orm";

import { capturedRequests } from "../schema.ts";
import { db } from "./db.ts";
import paths from "../paths.ts";

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
  error?: string;
  mechanism?: string;
  isWebSocket?: boolean;
  wsMessages?: WebSocketMessage[];
  attachment?: string | null;
}

export interface HttpNetworkEvent {
  event: string;
  requestId: string;
  timestamp: number;
  [key: string]: unknown;
}

export const attachmentsDir = nodePath.join(paths.data, "http-blobs");

function merge(req: CapturedRequest, event: HttpNetworkEvent): void {
  switch (event.event) {
    case "requestWillBeSent": {
      const r = event.request as
        | {
            method: string;
            url: string;
            headers: Record<string, string>;
            body?: string;
          }
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
        | {
            url?: string;
            mimeType?: string;
            statusCode?: number;
            headers?: Record<string, string>;
          }
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
      } catch {
        /* ignore */
      }
      break;
    }
    case "loadingFinished": {
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

export function upsert(
  deviceId: string,
  identifier: string,
  event: HttpNetworkEvent,
): string | null {
  const requestId = event.requestId || "unknown";

  const existing = db
    .select({
      data: capturedRequests.data,
      attachment: capturedRequests.attachment,
    })
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
  let attachment: string | null;

  if (existing) {
    req = JSON.parse(existing.data);
    attachment = existing.attachment;
  } else {
    req = {
      id: requestId,
      method: "",
      url: "",
      requestHeaders: {},
      size: 0,
      startTime: event.timestamp,
    };
    attachment = nodePath.join(attachmentsDir, randomUUID());
  }

  merge(req, event);
  req.attachment = attachment;

  db.insert(capturedRequests)
    .values({
      deviceId,
      identifier,
      requestId,
      data: JSON.stringify(req),
      attachment,
    })
    .onConflictDoUpdate({
      target: [
        capturedRequests.deviceId,
        capturedRequests.identifier,
        capturedRequests.requestId,
      ],
      set: {
        data: JSON.stringify(req),
        updatedAt: new Date().toISOString(),
      },
    })
    .run();

  return attachment;
}

export function query(
  deviceId: string,
  identifier: string,
  options: { limit?: number; offset?: number } = {},
): CapturedRequest[] {
  const { limit = 5000, offset = 0 } = options;

  const rows = db
    .select({
      data: capturedRequests.data,
      attachment: capturedRequests.attachment,
    })
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

  return rows.map((r) => {
    const req = JSON.parse(r.data) as CapturedRequest;
    req.attachment = r.attachment ?? null;
    return req;
  });
}

export function getAttachmentPath(
  deviceId: string,
  identifier: string,
  requestId: string,
): string | null {
  const row = db
    .select({ attachment: capturedRequests.attachment })
    .from(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
        eq(capturedRequests.requestId, requestId),
      ),
    )
    .get();

  return row?.attachment ?? null;
}

export function count(deviceId: string, identifier: string): number {
  const result = db
    .select({ count: countFn() })
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

export function rm(deviceId: string, identifier: string): void {
  // Clean up attachment files before deleting records
  const rows = db
    .select({ attachment: capturedRequests.attachment })
    .from(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
      ),
    )
    .all();

  rows.forEach((row) => {
    if (!row.attachment) return;
    fs.promises.unlink(row.attachment).catch(() => {});
  });

  db.delete(capturedRequests)
    .where(
      and(
        eq(capturedRequests.deviceId, deviceId),
        eq(capturedRequests.identifier, identifier),
      ),
    )
    .run();
}
