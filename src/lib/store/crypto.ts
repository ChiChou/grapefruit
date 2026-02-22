import { crypto } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type CryptoRecord = typeof crypto.$inferSelect;

export class CryptoStore extends BaseLogStore<typeof crypto> {
  constructor(deviceId: string, identifier: string) {
    super(crypto, deviceId, identifier);
  }

  append(message: Record<string, unknown>, data?: Buffer | null): void {
    const extra = message.extra as Record<string, unknown> | undefined;
    const btrace = message.backtrace as string[] | undefined;
    db.insert(crypto)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        symbol: (message.symbol as string) || "unknown",
        direction: (message.dir as string) || "unknown",
        line: (message.line as string) || null,
        extra: extra ? JSON.stringify(extra) : null,
        backtrace: btrace?.length ? JSON.stringify(btrace) : null,
        data: data ?? null,
      })
      .run();
  }
}
