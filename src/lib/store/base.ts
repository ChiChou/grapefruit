import { eq, and, gt, desc, count as countFn, type SQL } from "drizzle-orm";
import type { SQLiteColumn, SQLiteTableWithColumns } from "drizzle-orm/sqlite-core";
import { db } from "./db.ts";

type LogTable = SQLiteTableWithColumns<{
  name: string;
  columns: {
    id: SQLiteColumn;
    deviceId: SQLiteColumn;
    identifier: SQLiteColumn;
    timestamp: SQLiteColumn;
  };
  schema: string | undefined;
  dialect: "sqlite";
}>;

export interface ExtraFilter {
  column: SQLiteColumn;
  queryParam: string;
}

export class BaseLogStore<TTable extends LogTable> {
  constructor(
    protected table: TTable,
    protected deviceId: string,
    protected identifier: string,
    protected extraFilters: ExtraFilter[] = [],
  ) {}

  query(
    options: {
      limit?: number;
      offset?: number;
      since?: string;
      filters?: Record<string, string | number | boolean | undefined>;
    } = {},
    defaultLimit = 1000,
  ): TTable["$inferSelect"][] {
    const { limit = defaultLimit, offset = 0, since, filters } = options;

    const conditions: SQL[] = [
      eq(this.table.deviceId, this.deviceId),
      eq(this.table.identifier, this.identifier),
    ];

    if (since) {
      conditions.push(gt(this.table.timestamp, since));
    }

    if (filters) {
      for (const filter of this.extraFilters) {
        const value = filters[filter.queryParam];
        if (value !== undefined) {
          conditions.push(eq(filter.column, value));
        }
      }
    }

    return db
      .select()
      .from(this.table)
      .where(and(...conditions))
      .orderBy(desc(this.table.id))
      .limit(limit)
      .offset(offset)
      .all() as TTable["$inferSelect"][];
  }

  count(filters?: Record<string, string | number | boolean>): number {
    const conditions: SQL[] = [
      eq(this.table.deviceId, this.deviceId),
      eq(this.table.identifier, this.identifier),
    ];

    if (filters) {
      for (const filter of this.extraFilters) {
        const value = filters[filter.queryParam];
        if (value !== undefined) {
          conditions.push(eq(filter.column, value));
        }
      }
    }

    const result = db
      .select({ count: countFn() })
      .from(this.table)
      .where(and(...conditions))
      .get();

    return result?.count ?? 0;
  }

  rm(): void {
    db.delete(this.table)
      .where(
        and(
          eq(this.table.deviceId, this.deviceId),
          eq(this.table.identifier, this.identifier),
        ),
      )
      .run();
  }
}
