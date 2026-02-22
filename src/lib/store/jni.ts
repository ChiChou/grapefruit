import { jni } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";
import type { JNIEvent } from "@agent/droid/hooks/jni";

export type JNIRecord = typeof jni.$inferSelect;

export class JNIStore extends BaseLogStore<typeof jni> {
  constructor(deviceId: string, identifier: string) {
    super(jni, deviceId, identifier, [
      { column: jni.method, queryParam: "method" },
    ]);
  }

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
        backtrace: null,
        library: rest.library ?? null,
      })
      .run();
  }
}
