import { mkdirSync } from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";

import * as schema from "../schema.ts";
import env from "../env.ts";
import { asset } from "../assets.ts";
import { drizzle, migrate } from "./sqlite.ts";

const dbDir = path.join(env.workdir, "data");
mkdirSync(dbDir, { recursive: true });
const dbPath = path.join(dbDir, "data.db");
const migrationsFolder = asset("drizzle");

export const db = drizzle(
  new DatabaseSync(dbPath),
  { schema },
);

migrate(db, { migrationsFolder });
