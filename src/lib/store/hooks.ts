import { hooks } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type HookRecord = typeof hooks.$inferSelect;

export interface HookInput {
  category: string;
  symbol: string;
  dir: string;
  line?: string;
  extra?: Record<string, unknown>;
  backtrace?: string[];
}

export class HookStore extends BaseLogStore<typeof hooks> {
  constructor(deviceId: string, identifier: string) {
    super(hooks, deviceId, identifier, [
      { column: hooks.category, queryParam: "category" },
    ]);
  }

  append(message: HookInput): void {
    db.insert(hooks)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        category: message.category || "unknown",
        symbol: message.symbol || "unknown",
        direction: message.dir || "unknown",
        line: message.line || null,
        extra: message.extra ? JSON.stringify(message.extra) : null,
        backtrace: message.backtrace?.length ? JSON.stringify(message.backtrace) : null,
      })
      .run();
  }
}
