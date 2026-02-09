import path from "node:path";

import { eq, and, gt, desc, count } from "drizzle-orm";
import { drizzle } from "drizzle-orm/bun-sqlite";
import { migrate } from "drizzle-orm/bun-sqlite/migrator";

import * as schema from "./schema.ts";
import { preferences, hooks } from "./schema.ts";
import paths from "./paths.ts";

const db = drizzle(path.join(paths.data, "data.db"), { schema });

const migrationsFolder = path.join(import.meta.dirname, "..", "..", "drizzle");
migrate(db, { migrationsFolder });

// Preferences

export function setPreference(key: string, value: any): void {
  db.insert(preferences)
    .values({ key, value: JSON.stringify(value) })
    .onConflictDoUpdate({
      target: preferences.key,
      set: { value: JSON.stringify(value) },
    })
    .run();
}

export function getPreference(key: string): any {
  const row = db
    .select({ value: preferences.value })
    .from(preferences)
    .where(eq(preferences.key, key))
    .get();
  if (row?.value) {
    return JSON.parse(row.value);
  }
  return null;
}

export function deletePreference(key: string): void {
  db.delete(preferences).where(eq(preferences.key, key)).run();
}

export function resetPreferences(): void {
  db.delete(preferences).run();
}

// Hook logs

export interface HookRecord {
  id: number;
  device_id: string;
  identifier: string;
  timestamp: string;
  category: string;
  symbol: string;
  direction: string;
  payload: string;
  created_at: string;
}

/**
 * Insert a hook message into the database
 */
export function insertHookLog(
  deviceId: string,
  identifier: string,
  message: Record<string, unknown>,
): void {
  db.insert(hooks)
    .values({
      deviceId,
      identifier,
      timestamp: new Date().toISOString(),
      category: (message.category as string) || "unknown",
      symbol: (message.symbol as string) || "unknown",
      direction: (message.dir as string) || "unknown",
      payload: JSON.stringify(message),
    })
    .run();
}

/**
 * Query hook records with optional filters
 */
export function queryHookLogs(
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

  return rows as unknown as HookRecord[];
}

/**
 * Get the total count of hook records
 */
export function countHookLogs(
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
    .select({ count: count() })
    .from(hooks)
    .where(and(...conditions))
    .get();

  return result?.count ?? 0;
}

/**
 * Delete all hook records for a session
 */
export function deleteHookLogs(deviceId: string, identifier: string): void {
  db.delete(hooks)
    .where(and(eq(hooks.deviceId, deviceId), eq(hooks.identifier, identifier)))
    .run();
}
