import { randomUUID } from "node:crypto";
import fs from "node:fs";
import nodePath from "node:path";
import { eq, and, desc, count as countFn } from "drizzle-orm";

import { nsurlRequests } from "../schema.ts";
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
  backtrace?: string[];
  isWebSocket?: boolean;
  wsMessages?: WebSocketMessage[];
  attachment?: string | null;
}

interface NSURLEventBase {
  requestId: string;
  timestamp: number;
}

interface RequestWillBeSentEvent extends NSURLEventBase {
  event: "requestWillBeSent";
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  redirectResponse?: {
    url?: string;
    mimeType?: string;
    expectedContentLength: number;
    statusCode?: number;
    headers?: Record<string, string>;
  };
}

interface ResponseReceivedEvent extends NSURLEventBase {
  event: "responseReceived";
  response: {
    url?: string;
    mimeType?: string;
    expectedContentLength: number;
    statusCode?: number;
    headers?: Record<string, string>;
  };
}

interface DataReceivedEvent extends NSURLEventBase {
  event: "dataReceived";
  dataLength: string;
}

interface LoadingFinishedEvent extends NSURLEventBase {
  event: "loadingFinished";
  hasBody?: boolean;
}

interface LoadingFailedEvent extends NSURLEventBase {
  event: "loadingFailed";
  error: string;
}

interface MechanismEvent extends NSURLEventBase {
  event: "mechanism";
  mechanism: string;
}

interface WebSocketMessageEvent extends NSURLEventBase {
  event: "webSocketSend" | "webSocketReceive";
  messageType: "data" | "string";
  dataLength?: number;
  message?: string;
  error?: string;
}

export type NSURLEvent =
  | RequestWillBeSentEvent
  | ResponseReceivedEvent
  | DataReceivedEvent
  | LoadingFinishedEvent
  | LoadingFailedEvent
  | MechanismEvent
  | WebSocketMessageEvent;

function merge(req: CapturedRequest, event: NSURLEvent): void {
  switch (event.event) {
    case "requestWillBeSent": {
      req.method = event.request.method;
      req.url = event.request.url;
      req.requestHeaders = event.request.headers || {};
      req.requestBody = event.request.body;
      break;
    }
    case "responseReceived": {
      req.statusCode = event.response.statusCode;
      req.mimeType = event.response.mimeType;
      req.responseHeaders = event.response.headers;
      if (event.response.url && !req.url) req.url = event.response.url;
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
      req.error = event.error;
      req.endTime = event.timestamp;
      req.duration = event.timestamp - req.startTime;
      break;
    }
    case "mechanism": {
      req.mechanism = event.mechanism;
      break;
    }
    case "webSocketSend":
    case "webSocketReceive": {
      req.isWebSocket = true;
      if (!req.method) req.method = "WS";
      if (!req.wsMessages) req.wsMessages = [];
      req.wsMessages.push({
        direction: event.event === "webSocketSend" ? "send" : "receive",
        messageType: event.messageType ?? "data",
        message: event.message,
        dataLength: event.dataLength ? Number(event.dataLength) : undefined,
        error: event.error,
        timestamp: event.timestamp,
      });
      break;
    }
  }
}

export class NSURLStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

  get attachmentsDir(): string {
    return nodePath.join(paths.cache, this.deviceId, this.identifier);
  }

  upsert(event: NSURLEvent): string | null {
    const requestId = event.requestId || "unknown";

    const existing = db
      .select({
        data: nsurlRequests.data,
        attachment: nsurlRequests.attachment,
      })
      .from(nsurlRequests)
      .where(
        and(
          eq(nsurlRequests.deviceId, this.deviceId),
          eq(nsurlRequests.identifier, this.identifier),
          eq(nsurlRequests.requestId, requestId),
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

    db.insert(nsurlRequests)
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
          nsurlRequests.deviceId,
          nsurlRequests.identifier,
          nsurlRequests.requestId,
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
        data: nsurlRequests.data,
        attachment: nsurlRequests.attachment,
      })
      .from(nsurlRequests)
      .where(
        and(
          eq(nsurlRequests.deviceId, this.deviceId),
          eq(nsurlRequests.identifier, this.identifier),
        ),
      )
      .orderBy(desc(nsurlRequests.id))
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
      .select({ attachment: nsurlRequests.attachment, mime: nsurlRequests.mime })
      .from(nsurlRequests)
      .where(
        and(
          eq(nsurlRequests.deviceId, this.deviceId),
          eq(nsurlRequests.identifier, this.identifier),
          eq(nsurlRequests.requestId, requestId),
        ),
      )
      .get();

    if (!row?.attachment) return null;

    return { path: row.attachment, mimeType: row.mime ?? undefined };
  }

  count(): number {
    const result = db
      .select({ count: countFn() })
      .from(nsurlRequests)
      .where(
        and(
          eq(nsurlRequests.deviceId, this.deviceId),
          eq(nsurlRequests.identifier, this.identifier),
        ),
      )
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    const rows = db
      .select({ attachment: nsurlRequests.attachment })
      .from(nsurlRequests)
      .where(
        and(
          eq(nsurlRequests.deviceId, this.deviceId),
          eq(nsurlRequests.identifier, this.identifier),
        ),
      )
      .all();

    rows.forEach((row) => {
      if (!row.attachment) return;
      fs.promises.unlink(row.attachment).catch(() => {});
    });

    db.delete(nsurlRequests)
      .where(
        and(
          eq(nsurlRequests.deviceId, this.deviceId),
          eq(nsurlRequests.identifier, this.identifier),
        ),
      )
      .run();
  }
}
