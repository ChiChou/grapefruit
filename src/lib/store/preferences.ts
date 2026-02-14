import { eq } from "drizzle-orm";
import { preferences } from "../schema.ts";
import { db } from "./db.ts";

export function set(key: string, value: any): void {
  db.insert(preferences)
    .values({ key, value: JSON.stringify(value) })
    .onConflictDoUpdate({
      target: preferences.key,
      set: { value: JSON.stringify(value) },
    })
    .run();
}

export function get(key: string): any {
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

export function rm(key: string): void {
  db.delete(preferences).where(eq(preferences.key, key)).run();
}

export function purge(): void {
  db.delete(preferences).run();
}
