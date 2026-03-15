import { crypto } from "../schema.ts";
import { db } from "./db.ts";
import { BaseLogStore } from "./base.ts";

export type CryptoRecord = typeof crypto.$inferSelect;

export interface CryptoInput {
  category?: string;
  symbol: string;
  dir: string;
  line?: string;
  extra?: Record<string, unknown>;
  backtrace?: string[];
}

export class CryptoStore extends BaseLogStore<typeof crypto> {
  constructor(deviceId: string, identifier: string) {
    super(crypto, deviceId, identifier);
  }

  append(message: CryptoInput, data?: Buffer | null): void {
    db.insert(crypto)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        category: message.category || null,
        symbol: message.symbol || "unknown",
        direction: message.dir || "unknown",
        line: message.line || null,
        extra: message.extra ? JSON.stringify(message.extra) : null,
        backtrace: message.backtrace?.length ? JSON.stringify(message.backtrace) : null,
        data: data ?? null,
      })
      .run();
  }
}
