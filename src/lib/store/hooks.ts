import { hooks } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type HookRecord = typeof hooks.$inferSelect;

export class HookStore extends BaseLogStore<typeof hooks> {
  constructor(deviceId: string, identifier: string) {
    super(hooks, deviceId, identifier, [
      { column: hooks.category, queryParam: "category" },
    ]);
  }

  append(message: Record<string, unknown>): void {
    const extra = message.extra as Record<string, unknown> | undefined;
    db.insert(hooks)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        category: (message.category as string) || "unknown",
        symbol: (message.symbol as string) || "unknown",
        direction: (message.dir as string) || "unknown",
        line: (message.line as string) || null,
        extra: extra ? JSON.stringify(extra) : null,
      })
      .run();
  }
}
