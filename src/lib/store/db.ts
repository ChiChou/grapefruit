import fs from "node:fs";
import path from "node:path";

import Database from "better-sqlite3";
import { drizzle } from "drizzle-orm/better-sqlite3";
import { migrate } from "drizzle-orm/better-sqlite3/migrator";
import type { BaseSQLiteDatabase } from "drizzle-orm/sqlite-core";
import * as schema from "../schema.ts";
import env from "../env.ts";
import { asset } from "../assets.ts";

const dbDir = path.join(env.workdir, "data");
await fs.promises.mkdir(dbDir, { recursive: true });
const dbPath = path.join(dbDir, "data.db");
const migrationsFolder = await asset("drizzle");

export const db: BaseSQLiteDatabase<"sync", any, typeof schema> = drizzle(
  new Database(dbPath),
  { schema },
);

migrate(db, { migrationsFolder });
