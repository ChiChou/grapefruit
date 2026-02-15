import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { crypto } from "../schema.ts";
import { db } from "./db.ts";

export interface CryptoRecord {
  id: number;
  timestamp: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra: string | null;
  backtrace: string | null;
  data: Buffer | null;
  createdAt: string;
}

export class CryptoStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

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

  query(
    options: { limit?: number; offset?: number; since?: string } = {},
  ): CryptoRecord[] {
    const { limit = 1000, offset = 0, since } = options;

    const conditions = [
      eq(crypto.deviceId, this.deviceId),
      eq(crypto.identifier, this.identifier),
    ];

    if (since) {
      conditions.push(gt(crypto.timestamp, since));
    }

    const rows = db
      .select()
      .from(crypto)
      .where(and(...conditions))
      .orderBy(desc(crypto.id))
      .limit(limit)
      .offset(offset)
      .all();

    return rows as CryptoRecord[];
  }

  count(): number {
    const result = db
      .select({ count: countFn() })
      .from(crypto)
      .where(
        and(
          eq(crypto.deviceId, this.deviceId),
          eq(crypto.identifier, this.identifier),
        ),
      )
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    db.delete(crypto)
      .where(
        and(
          eq(crypto.deviceId, this.deviceId),
          eq(crypto.identifier, this.identifier),
        ),
      )
      .run();
  }
}
