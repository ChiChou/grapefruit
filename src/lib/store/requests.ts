import { randomUUID } from "node:crypto";
import fs from "node:fs";
import nodePath from "node:path";
import { eq, and, desc, count as countFn } from "drizzle-orm";

import { requests } from "../schema.ts";
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

export class HttpStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

  get attachmentsDir(): string {
    return nodePath.join(paths.cache, this.deviceId, this.identifier);
  }

  upsert(event: HttpNetworkEvent): string | null {
    const requestId = event.requestId || "unknown";

    const existing = db
      .select({
        data: requests.data,
        attachment: requests.attachment,
      })
      .from(requests)
      .where(
        and(
          eq(requests.deviceId, this.deviceId),
          eq(requests.identifier, this.identifier),
          eq(requests.requestId, requestId),
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
      attachment = nodePath.join(this.attachmentsDir, randomUUID());
    }

    merge(req, event);
    req.attachment = attachment;

    db.insert(requests)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        requestId,
        data: JSON.stringify(req),
        attachment,
        mime: req.mimeType ?? null,
      })
      .onConflictDoUpdate({
        target: [
          requests.deviceId,
          requests.identifier,
          requests.requestId,
        ],
        set: {
          data: JSON.stringify(req),
          mime: req.mimeType ?? null,
          updatedAt: new Date().toISOString(),
        },
      })
      .run();

    return attachment;
  }

  query(options: { limit?: number; offset?: number } = {}): CapturedRequest[] {
    const { limit = 5000, offset = 0 } = options;

    const rows = db
      .select({
        data: requests.data,
        attachment: requests.attachment,
      })
      .from(requests)
      .where(
        and(
          eq(requests.deviceId, this.deviceId),
          eq(requests.identifier, this.identifier),
        ),
      )
      .orderBy(desc(requests.id))
      .limit(limit)
      .offset(offset)
      .all();

    return rows.map((r) => {
      const req = JSON.parse(r.data) as CapturedRequest;
      req.attachment = r.attachment ?? null;
      return req;
    });
  }

  getAttachment(requestId: string): {
    path: string;
    mimeType?: string;
  } | null {
    const row = db
      .select({ attachment: requests.attachment, mime: requests.mime })
      .from(requests)
      .where(
        and(
          eq(requests.deviceId, this.deviceId),
          eq(requests.identifier, this.identifier),
          eq(requests.requestId, requestId),
        ),
      )
      .get();

    if (!row?.attachment) return null;

    return { path: row.attachment, mimeType: row.mime ?? undefined };
  }

  count(): number {
    const result = db
      .select({ count: countFn() })
      .from(requests)
      .where(
        and(
          eq(requests.deviceId, this.deviceId),
          eq(requests.identifier, this.identifier),
        ),
      )
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    const rows = db
      .select({ attachment: requests.attachment })
      .from(requests)
      .where(
        and(
          eq(requests.deviceId, this.deviceId),
          eq(requests.identifier, this.identifier),
        ),
      )
      .all();

    rows.forEach((row) => {
      if (!row.attachment) return;
      fs.promises.unlink(row.attachment).catch(() => {});
    });

    db.delete(requests)
      .where(
        and(
          eq(requests.deviceId, this.deviceId),
          eq(requests.identifier, this.identifier),
        ),
      )
      .run();
  }
}
