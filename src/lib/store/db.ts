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

const client = new DatabaseSync(dbPath);
client.exec("PRAGMA busy_timeout = 5000");
export const db = drizzle(client, { schema });

migrate(db, { migrationsFolder });
