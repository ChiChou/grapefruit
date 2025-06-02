import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import paths from "./paths.ts";

const DATABASE_VERSION = 1;

const db = new DatabaseSync(path.join(paths.data, "data.db"), { open: true });
const result = db.prepare("PRAGMA user_version").get();

if (result) {
  const version = result["user_version"] as number;

  if (version === 0) {
    db.exec(`PRAGMA user_version = ${DATABASE_VERSION};`);
    db.exec(`CREATE TABLE IF NOT EXISTS preferences (
                key TEXT PRIMARY KEY,
                value TEXT
            );`);
  } else if (version !== DATABASE_VERSION) {
    // migration not supported at the moment, bail out
    throw new Error(`Database version ${version} does not match app`);
  }
}

export function setPref(key: string, value: any): void {
  const stmt = db.prepare(
    "INSERT OR REPLACE INTO preferences (key, value) VALUES (?, ?);",
  );
  if (stmt.run(key, JSON.stringify(value)).changes !== 1) {
    throw new Error(`Failed to set preference ${key}`);
  }
}

export function getPref(key: string): any {
  const stmt = db.prepare("SELECT value FROM preferences WHERE key = ?;");
  const result = stmt.get(key);
  if (result) {
    return JSON.parse(result["value"] as string);
  }
  return null;
}

export function delPref(key: string): void {
  const stmt = db.prepare("DELETE FROM preferences WHERE key = ?;");
  stmt.run(key);
}

export function resetPrefs(): void {
  db.exec("DELETE FROM preferences;");
}

// todo: persist hook logs
