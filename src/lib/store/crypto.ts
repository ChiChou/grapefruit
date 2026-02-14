import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { cryptoLogs } from "../schema.ts";
import { db } from "./db.ts";

export interface CryptoRecord {
  id: number;
  deviceId: string;
  identifier: string;
  timestamp: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra: string | null;
  backtrace: string | null;
  data: Buffer | null;
  createdAt: string;
}

export function append(
  deviceId: string,
  identifier: string,
  message: Record<string, unknown>,
  data?: Buffer | null,
): void {
  const extra = message.extra as Record<string, unknown> | undefined;
  const btrace = message.backtrace as string[] | undefined;
  db.insert(cryptoLogs)
    .values({
      deviceId,
      identifier,
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

export function query(
  deviceId: string,
  identifier: string,
  options: { limit?: number; offset?: number; since?: string } = {},
): CryptoRecord[] {
  const { limit = 1000, offset = 0, since } = options;

  const conditions = [
    eq(cryptoLogs.deviceId, deviceId),
    eq(cryptoLogs.identifier, identifier),
  ];

  if (since) {
    conditions.push(gt(cryptoLogs.timestamp, since));
  }

  const rows = db
    .select()
    .from(cryptoLogs)
    .where(and(...conditions))
    .orderBy(desc(cryptoLogs.id))
    .limit(limit)
    .offset(offset)
    .all();

  return rows as CryptoRecord[];
}

export function count(deviceId: string, identifier: string): number {
  const result = db
    .select({ count: countFn() })
    .from(cryptoLogs)
    .where(
      and(
        eq(cryptoLogs.deviceId, deviceId),
        eq(cryptoLogs.identifier, identifier),
      ),
    )
    .get();

  return result?.count ?? 0;
}

export function rm(deviceId: string, identifier: string): void {
  db.delete(cryptoLogs)
    .where(
      and(
        eq(cryptoLogs.deviceId, deviceId),
        eq(cryptoLogs.identifier, identifier),
      ),
    )
    .run();
}
