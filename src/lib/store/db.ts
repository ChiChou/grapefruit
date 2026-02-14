import path from "node:path";

import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import * as schema from "../schema.ts";
import paths from "../paths.ts";
import { asset } from "../assets.ts";

const dbPath = path.join(paths.data, "data.db");
const migrationsFolder = await asset("drizzle");

// workaround to support both bun and node.js runtime
export const db: BaseSQLiteDatabase<"sync", any, typeof schema> = await (async () => {
  if (typeof globalThis.Bun === "undefined") {
    const { default: Database } = (await import("better-sqlite3")) as any;
    const { drizzle } = await import("drizzle-orm/better-sqlite3");
    const { migrate } = await import("drizzle-orm/better-sqlite3/migrator");
    const db = drizzle(new Database(dbPath), { schema });
    migrate(db, { migrationsFolder });
    return db;
  }

  const { drizzle } = await import("drizzle-orm/bun-sqlite");
  const { migrate } = await import("drizzle-orm/bun-sqlite/migrator");
  const db = drizzle(dbPath, { schema });
  migrate(db, { migrationsFolder });
  return db;
})();
