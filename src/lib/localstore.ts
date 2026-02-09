import path from "node:path";

import paths from "./paths.ts";
import { createDatabase, type Database } from "./sqlite.ts";

const DATABASE_VERSION = 0;

let dbInstance: Database;

function get(): Database {
  if (dbInstance) {
    return dbInstance;
  }

  const db = createDatabase(path.join(paths.data, "data.db"));
  const result = db.prepare("PRAGMA user_version").get();

  const version = result?.user_version as number;
  // we are going to use ORM libraries in the future, so won't implement migration for now
  if (version !== DATABASE_VERSION) {
    console.error(
      `Database version mismatch: expected ${DATABASE_VERSION}, got ${version}.
      Currently we do not support migration, please delete the database file at ${path.join(paths.data, "data.db")} to reset the local store.`,
    );

    throw new Error(
      `Database version mismatch: expected ${DATABASE_VERSION}, got ${version}`,
    );
  }

  // preferences
  db.exec(`CREATE TABLE IF NOT EXISTS preferences (
            key TEXT PRIMARY KEY,
            value TEXT
        );`);

  // preferences end

  // hooks
  db.exec(`
    CREATE TABLE IF NOT EXISTS hooks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      device_id TEXT NOT NULL,
      identifier TEXT NOT NULL,
      timestamp TEXT NOT NULL,
      category TEXT NOT NULL,
      symbol TEXT NOT NULL,
      direction TEXT NOT NULL,
      payload TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
  `);
  db.exec(
    `CREATE INDEX IF NOT EXISTS idx_hooks_device_identifier ON hooks(device_id, identifier)`,
  );
  db.exec(`CREATE INDEX IF NOT EXISTS idx_hooks_timestamp ON hooks(timestamp)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_hooks_category ON hooks(category)`);

  // hooks end

  dbInstance = db;
  return dbInstance;
}

export function setPref(key: string, value: any): void {
  const db = get();
  const stmt = db.prepare(
    "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?);",
  );
  if (stmt.run(key, JSON.stringify(value)).changes !== 1) {
    throw new Error(`Failed to set preference ${key}`);
  }
}

export function getPref(key: string): any {
  const db = get();
  const stmt = db.prepare("SELECT value FROM preferences WHERE key = ?;");
  const result = stmt.get(key);
  if (result) {
    return JSON.parse(result["value"] as string);
  }
  return null;
}

export function delPref(key: string): void {
  const db = get();
  const stmt = db.prepare("DELETE FROM preferences WHERE key = ?;");
  stmt.run(key);
}

export function resetPrefs(): void {
  const db = get();
  db.exec("DELETE FROM preferences;");
}

// Hook storage

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
export function insertHook(
  deviceId: string,
  identifier: string,
  message: Record<string, unknown>,
): void {
  const db = get();

  const stmt = db.prepare(`
    INSERT INTO hooks (device_id, identifier, timestamp, category, symbol, direction, payload)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
    deviceId,
    identifier,
    new Date().toISOString(),
    (message.category as string) || "unknown",
    (message.symbol as string) || "unknown",
    (message.dir as string) || "unknown",
    JSON.stringify(message),
  );
}

/**
 * Query hook records with optional filters
 */
export function queryHooks(
  deviceId: string,
  identifier: string,
  options: {
    limit?: number;
    offset?: number;
    category?: string;
    since?: string;
  } = {},
): HookRecord[] {
  const db = get();
  const { limit = 1000, offset = 0, category, since } = options;

  const conditions: string[] = ["device_id = ?", "identifier = ?"];
  const params: (string | number)[] = [deviceId, identifier];

  if (category) {
    conditions.push("category = ?");
    params.push(category);
  }

  if (since) {
    conditions.push("timestamp > ?");
    params.push(since);
  }

  const sql = `SELECT * FROM hooks WHERE ${conditions.join(" AND ")} ORDER BY id DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const stmt = db.prepare(sql);
  return stmt.all(...params) as unknown as HookRecord[];
}

/**
 * Get the total count of hook records
 */
export function countHooks(
  deviceId: string,
  identifier: string,
  category?: string,
): number {
  const db = get();

  const conditions: string[] = ["device_id = ?", "identifier = ?"];
  const params: string[] = [deviceId, identifier];

  if (category) {
    conditions.push("category = ?");
    params.push(category);
  }

  const sql = `SELECT COUNT(*) as count FROM hooks WHERE ${conditions.join(" AND ")}`;
  const stmt = db.prepare(sql);
  const result = stmt.get(...params) as { count: number };
  return result.count;
}

/**
 * Clear all hook records for a session
 */
export function clearHooks(deviceId: string, identifier: string): void {
  const db = get();
  const stmt = db.prepare(
    "DELETE FROM hooks WHERE device_id = ? AND identifier = ?",
  );
  stmt.run(deviceId, identifier);
}

/**
 * Delete all hooks for a device/identifier (alias for clearHooks for API compatibility)
 */
export function deleteHooks(deviceId: string, identifier: string): void {
  clearHooks(deviceId, identifier);
}
