import { eq, and, desc, count as countFn } from "drizzle-orm";
import { hermes } from "../schema.ts";
import { db } from "./db.ts";

export type HermesRecord = typeof hermes.$inferSelect;

export class HermesStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

  append(
    message: { url: string; hash: string; size: number },
    data: Buffer,
  ): void {
    db.insert(hermes)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        url: message.url,
        hash: message.hash,
        size: message.size,
        data,
      })
      .onConflictDoNothing()
      .run();
  }

  query(options: {
    limit?: number;
    offset?: number;
  } = {}): HermesRecord[] {
    const { limit = 100, offset = 0 } = options;

    return db
      .select()
      .from(hermes)
      .where(
        and(
          eq(hermes.deviceId, this.deviceId),
          eq(hermes.identifier, this.identifier),
        ),
      )
      .orderBy(desc(hermes.id))
      .limit(limit)
      .offset(offset)
      .all() as HermesRecord[];
  }

  count(): number {
    const result = db
      .select({ count: countFn() })
      .from(hermes)
      .where(
        and(
          eq(hermes.deviceId, this.deviceId),
          eq(hermes.identifier, this.identifier),
        ),
      )
      .get();

    return result?.count ?? 0;
  }

  getBlob(id: number): { data: Buffer; url: string } | null {
    const row = db
      .select({ data: hermes.data, url: hermes.url })
      .from(hermes)
      .where(
        and(
          eq(hermes.id, id),
          eq(hermes.deviceId, this.deviceId),
          eq(hermes.identifier, this.identifier),
        ),
      )
      .get();

    if (!row) return null;
    return { data: Buffer.from(row.data), url: row.url };
  }

  rmOne(id: number): void {
    db.delete(hermes)
      .where(
        and(
          eq(hermes.id, id),
          eq(hermes.deviceId, this.deviceId),
          eq(hermes.identifier, this.identifier),
        ),
      )
      .run();
  }

  rm(): void {
    db.delete(hermes)
      .where(
        and(
          eq(hermes.deviceId, this.deviceId),
          eq(hermes.identifier, this.identifier),
        ),
      )
      .run();
  }
}
