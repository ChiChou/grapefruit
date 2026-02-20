import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { xpcLogs } from "../schema.ts";
import { db } from "./db.ts";

export interface XPCRecord {
  id: number;
  timestamp: string;
  protocol: string;
  event: string;
  direction: string;
  service: string | null;
  peer: number | null;
  message: string;
  backtrace: string | null;
  createdAt: string;
}

export class XPCStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

  append(payload: Record<string, unknown>): void {
    const message = payload.message as Record<string, unknown> | undefined;
    const isNsxpc = message?.type === "nsxpc";
    const backtrace = payload.backtrace as string[] | undefined;

    db.insert(xpcLogs)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        protocol: isNsxpc ? "nsxpc" : "xpc",
        event: (payload.event as string) || "unknown",
        direction: (payload.dir as string) || "unknown",
        service: (payload.name as string) || null,
        peer: (payload.peer as number) || null,
        message: message ? JSON.stringify(message) : "{}",
        backtrace: backtrace?.length ? JSON.stringify(backtrace) : null,
      })
      .run();
  }

  query(
    options: {
      limit?: number;
      offset?: number;
      since?: string;
      protocol?: string;
    } = {},
  ): XPCRecord[] {
    const { limit = 5000, offset = 0, since, protocol } = options;

    const conditions = [
      eq(xpcLogs.deviceId, this.deviceId),
      eq(xpcLogs.identifier, this.identifier),
    ];

    if (since) {
      conditions.push(gt(xpcLogs.timestamp, since));
    }

    if (protocol) {
      conditions.push(eq(xpcLogs.protocol, protocol));
    }

    return db
      .select()
      .from(xpcLogs)
      .where(and(...conditions))
      .orderBy(desc(xpcLogs.id))
      .limit(limit)
      .offset(offset)
      .all() as XPCRecord[];
  }

  count(protocol?: string): number {
    const conditions = [
      eq(xpcLogs.deviceId, this.deviceId),
      eq(xpcLogs.identifier, this.identifier),
    ];

    if (protocol) {
      conditions.push(eq(xpcLogs.protocol, protocol));
    }

    const result = db
      .select({ count: countFn() })
      .from(xpcLogs)
      .where(and(...conditions))
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    db.delete(xpcLogs)
      .where(
        and(
          eq(xpcLogs.deviceId, this.deviceId),
          eq(xpcLogs.identifier, this.identifier),
        ),
      )
      .run();
  }
}
