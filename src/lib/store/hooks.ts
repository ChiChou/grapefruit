import { eq, and, gt, desc, count as countFn } from "drizzle-orm";
import { hooks } from "../schema.ts";
import { db } from "./db.ts";

export interface HookRecord {
  id: number;
  timestamp: string;
  category: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra: string | null;
  createdAt: string;
}

export class HookStore {
  constructor(
    private deviceId: string,
    private identifier: string,
  ) {}

  append(message: Record<string, unknown>): void {
    const extra = message.extra as Record<string, unknown> | undefined;
    db.insert(hooks)
      .values({
        deviceId: this.deviceId,
        identifier: this.identifier,
        timestamp: new Date().toISOString(),
        category: (message.category as string) || "unknown",
        symbol: (message.symbol as string) || "unknown",
        direction: (message.dir as string) || "unknown",
        line: (message.line as string) || null,
        extra: extra ? JSON.stringify(extra) : null,
      })
      .run();
  }

  query(
    options: {
      limit?: number;
      offset?: number;
      category?: string;
      since?: string;
    } = {},
  ): HookRecord[] {
    const { limit = 1000, offset = 0, category, since } = options;

    const conditions = [
      eq(hooks.deviceId, this.deviceId),
      eq(hooks.identifier, this.identifier),
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

  count(category?: string): number {
    const conditions = [
      eq(hooks.deviceId, this.deviceId),
      eq(hooks.identifier, this.identifier),
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

  rm(): void {
    db.delete(hooks)
      .where(
        and(
          eq(hooks.deviceId, this.deviceId),
          eq(hooks.identifier, this.identifier),
        ),
      )
      .run();
  }
}
