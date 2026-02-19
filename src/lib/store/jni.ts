import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { jni } from "../schema.ts";
import { db } from "./db.ts";
import type { JNIEvent } from "@agent/droid/hooks/jni";

export interface JNIRecord {
  id: number;
  timestamp: string;
  type: string;
  method: string;
  callType: string;
  threadId: number | null;
  args: string | null;
  ret: string | null;
  backtrace: string | null;
  library: string | null;
  createdAt: string;
}

export class JNIStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

  append(event: JNIEvent): void {
    const { subject: _, ...rest } = event;
    db.insert(jni)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        type: rest.type,
        method: rest.method,
        callType: rest.callType,
        threadId: rest.threadId,
        args: Array.isArray(rest.args) ? JSON.stringify(rest.args) : null,
        ret: rest.ret,
        backtrace: null, // backtrace not yet enabled in jni module
        library: "library" in rest ? (rest as any).library : null,
      })
      .run();
  }

  query(
    options: {
      limit?: number;
      offset?: number;
      since?: string;
      method?: string;
    } = {},
  ): JNIRecord[] {
    const { limit = 5000, offset = 0, since, method } = options;

    const conditions = [
      eq(jni.deviceId, this.deviceId),
      eq(jni.identifier, this.identifier),
    ];

    if (since) {
      conditions.push(gt(jni.timestamp, since));
    }

    if (method) {
      conditions.push(eq(jni.method, method));
    }

    return db
      .select()
      .from(jni)
      .where(and(...conditions))
      .orderBy(desc(jni.id))
      .limit(limit)
      .offset(offset)
      .all() as JNIRecord[];
  }

  count(method?: string): number {
    const conditions = [
      eq(jni.deviceId, this.deviceId),
      eq(jni.identifier, this.identifier),
    ];

    if (method) {
      conditions.push(eq(jni.method, method));
    }

    const result = db
      .select({ count: countFn() })
      .from(jni)
      .where(and(...conditions))
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    db.delete(jni)
      .where(
        and(
          eq(jni.deviceId, this.deviceId),
          eq(jni.identifier, this.identifier),
        ),
      )
      .run();
  }
}
