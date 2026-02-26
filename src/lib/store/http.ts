import { randomUUID } from "node:crypto";
import fs from "node:fs";
import nodePath from "node:path";
import { eq, and, desc, count as countFn } from "drizzle-orm";

import { httpRequests } from "../schema.ts";
import { db } from "./db.ts";
import paths from "../paths.ts";
import type { CapturedRequest } from "./nsurl.ts";

export interface HttpEvent {
  type: string;
  requestId: string;
  timestamp: number;
  [key: string]: unknown;
}

function merge(req: CapturedRequest, event: HttpEvent): void {
  switch (event.type) {
    case "callStart": {
      const r = event.request as
        | {
            method: string;
            url: string;
            headers: Record<string, string>;
            body?: string;
            bodyLength?: number;
          }
        | undefined;
      if (!r) break;
      req.method = r.method;
      req.url = r.url;
      req.requestHeaders = r.headers || {};
      req.requestBody = r.body;
      if (event.backtrace) req.backtrace = event.backtrace as string[];
      break;
    }
    case "responseHeaders": {
      const r = event.response as
        | {
            url?: string;
            statusCode?: number;
            statusMessage?: string;
            headers?: Record<string, string>;
            contentType?: string;
            contentLength?: number;
          }
        | undefined;
      if (!r) break;
      req.statusCode = r.statusCode;
      req.mimeType = r.contentType;
      req.responseHeaders = r.headers;
      if (r.url && !req.url) req.url = r.url;
      break;
    }
    case "responseBody": {
      try {
        req.size += Number(event.bodyLength ?? 0);
      } catch { /* ignore */ }
      break;
    }
    case "responseBodyChunk": {
      try {
        req.size += Number(event.bytesRead ?? event.charsRead ?? 0);
      } catch { /* ignore */ }
      break;
    }
    case "responseBodyEnd": {
      if (!req.endTime) {
        req.endTime = event.timestamp;
        req.duration = event.timestamp - req.startTime;
      }
      break;
    }
    case "callEnd": {
      req.endTime = event.timestamp;
      req.duration = event.timestamp - req.startTime;
      break;
    }
    case "callFailed": {
      req.error = event.error as string | undefined;
      req.endTime = event.timestamp;
      req.duration = event.timestamp - req.startTime;
      break;
    }
    case "wsOpen": {
      req.isWebSocket = true;
      if (!req.method) req.method = "WS";
      if (event.url) req.url = event.url as string;
      break;
    }
    case "wsMessage": {
      req.isWebSocket = true;
      if (!req.method) req.method = "WS";
      if (!req.wsMessages) req.wsMessages = [];
      req.wsMessages.push({
        direction: (event.direction as "send" | "receive") ?? "receive",
        messageType: (event.messageType as "data" | "string") ?? "data",
        message: event.message as string | undefined,
        dataLength: event.dataLength ? Number(event.dataLength) : undefined,
        timestamp: event.timestamp,
      });
      break;
    }
    case "wsClose": {
      req.isWebSocket = true;
      if (!req.wsMessages) req.wsMessages = [];
      req.wsMessages.push({
        direction: (event.direction as "send" | "receive") ?? "receive",
        messageType: "string",
        message: `Close: code=${event.code} reason=${event.reason ?? ""}`,
        timestamp: event.timestamp,
      });
      break;
    }
    case "wsFailure": {
      req.error = event.error as string | undefined;
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

  upsert(event: HttpEvent): string | null {
    const requestId = event.requestId || "unknown";

    const existing = db
      .select({
        data: httpRequests.data,
        attachment: httpRequests.attachment,
      })
      .from(httpRequests)
      .where(
        and(
          eq(httpRequests.deviceId, this.deviceId),
          eq(httpRequests.identifier, this.identifier),
          eq(httpRequests.requestId, requestId),
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

    db.insert(httpRequests)
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
          httpRequests.deviceId,
          httpRequests.identifier,
          httpRequests.requestId,
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
        data: httpRequests.data,
        attachment: httpRequests.attachment,
      })
      .from(httpRequests)
      .where(
        and(
          eq(httpRequests.deviceId, this.deviceId),
          eq(httpRequests.identifier, this.identifier),
        ),
      )
      .orderBy(desc(httpRequests.id))
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
      .select({ attachment: httpRequests.attachment, mime: httpRequests.mime })
      .from(httpRequests)
      .where(
        and(
          eq(httpRequests.deviceId, this.deviceId),
          eq(httpRequests.identifier, this.identifier),
          eq(httpRequests.requestId, requestId),
        ),
      )
      .get();

    if (!row?.attachment) return null;

    return { path: row.attachment, mimeType: row.mime ?? undefined };
  }

  count(): number {
    const result = db
      .select({ count: countFn() })
      .from(httpRequests)
      .where(
        and(
          eq(httpRequests.deviceId, this.deviceId),
          eq(httpRequests.identifier, this.identifier),
        ),
      )
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    const rows = db
      .select({ attachment: httpRequests.attachment })
      .from(httpRequests)
      .where(
        and(
          eq(httpRequests.deviceId, this.deviceId),
          eq(httpRequests.identifier, this.identifier),
        ),
      )
      .all();

    rows.forEach((row) => {
      if (!row.attachment) return;
      fs.promises.unlink(row.attachment).catch(() => {});
    });

    db.delete(httpRequests)
      .where(
        and(
          eq(httpRequests.deviceId, this.deviceId),
          eq(httpRequests.identifier, this.identifier),
        ),
      )
      .run();
  }
}
