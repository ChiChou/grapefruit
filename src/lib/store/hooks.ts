import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { hooks } from "../schema.ts";
import { db } from "./db.ts";

export interface HookRecord {
  id: number;
  deviceId: string;
  identifier: string;
  timestamp: string;
  category: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra: string | null;
  createdAt: string;
}

export function append(
  deviceId: string,
  identifier: string,
  message: Record<string, unknown>,
): void {
  const extra = message.extra as Record<string, unknown> | undefined;
  db.insert(hooks)
    .values({
      deviceId,
      identifier,
      timestamp: new Date().toISOString(),
      category: (message.category as string) || "unknown",
      symbol: (message.symbol as string) || "unknown",
      direction: (message.dir as string) || "unknown",
      line: (message.line as string) || null,
      extra: extra ? JSON.stringify(extra) : null,
    })
    .run();
}

export function query(
  deviceId: string,
  identifier: string,
  options: {
    limit?: number;
    offset?: number;
    category?: string;
    since?: string;
  } = {},
): HookRecord[] {
  const { limit = 1000, offset = 0, category, since } = options;

  const conditions = [
    eq(hooks.deviceId, deviceId),
    eq(hooks.identifier, identifier),
  ];

  if (category) {
    conditions.push(eq(hooks.category, category));
  }

  if (since) {
    conditions.push(gt(hooks.timestamp, since));
  }

  const rows = db
    .select()
    .from(hooks)
    .where(and(...conditions))
    .orderBy(desc(hooks.id))
    .limit(limit)
    .offset(offset)
    .all();

  return rows as HookRecord[];
}

export function count(
  deviceId: string,
  identifier: string,
  category?: string,
): number {
  const conditions = [
    eq(hooks.deviceId, deviceId),
    eq(hooks.identifier, identifier),
  ];

  if (category) {
    conditions.push(eq(hooks.category, category));
  }

  const result = db
    .select({ count: countFn() })
    .from(hooks)
    .where(and(...conditions))
    .get();

  return result?.count ?? 0;
}

export function rm(deviceId: string, identifier: string): void {
  db.delete(hooks)
    .where(and(eq(hooks.deviceId, deviceId), eq(hooks.identifier, identifier)))
    .run();
}
