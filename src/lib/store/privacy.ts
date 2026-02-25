import { privacy } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type PrivacyRecord = typeof privacy.$inferSelect;

export interface PrivacyInput {
  category: string;
  severity: string;
  symbol: string;
  dir: string;
  line?: string;
  extra?: Record<string, unknown>;
  backtrace?: string[];
}

export class PrivacyStore extends BaseLogStore<typeof privacy> {
  constructor(deviceId: string, identifier: string) {
    super(privacy, deviceId, identifier, [
      { column: privacy.category, queryParam: "category" },
      { column: privacy.severity, queryParam: "severity" },
    ]);
  }

  append(message: PrivacyInput): void {
    db.insert(privacy)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        category: message.category || "unknown",
        severity: message.severity || "unknown",
        symbol: message.symbol || "unknown",
        direction: message.dir || "unknown",
        line: message.line || null,
        extra: message.extra ? JSON.stringify(message.extra) : null,
        backtrace: message.backtrace ? JSON.stringify(message.backtrace) : null,
      })
      .run();
  }
}
