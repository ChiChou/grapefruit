import { privacy } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type PrivacyRecord = typeof privacy.$inferSelect;

export class PrivacyStore extends BaseLogStore<typeof privacy> {
  constructor(deviceId: string, identifier: string) {
    super(privacy, deviceId, identifier, [
      { column: privacy.category, queryParam: "category" },
      { column: privacy.severity, queryParam: "severity" },
    ]);
  }

  append(message: Record<string, unknown>): void {
    const extra = message.extra as Record<string, unknown> | undefined;
    const bt = message.backtrace as string[] | undefined;
    db.insert(privacy)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        category: (message.category as string) || "unknown",
        severity: (message.severity as string) || "unknown",
        symbol: (message.symbol as string) || "unknown",
        direction: (message.dir as string) || "unknown",
        line: (message.line as string) || null,
        extra: extra ? JSON.stringify(extra) : null,
        backtrace: bt ? JSON.stringify(bt) : null,
      })
      .run();
  }
}
