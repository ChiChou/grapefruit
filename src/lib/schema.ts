import { sql } from "drizzle-orm";
import { sqliteTable, text, integer, index } from "drizzle-orm/sqlite-core";

export const preferences = sqliteTable("preferences", {
  key: text("key").primaryKey(),
  value: text("value"),
});

export const capturedRequests = sqliteTable(
  "captured_requests",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    requestId: text("request_id").notNull(),
    data: text("data").notNull(),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_captured_requests_device_identifier").on(
      table.deviceId,
      table.identifier,
    ),
    index("idx_captured_requests_request_id").on(
      table.deviceId,
      table.identifier,
      table.requestId,
    ),
  ],
);

export const hooks = sqliteTable(
  "hooks",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    timestamp: text("timestamp").notNull(),
    category: text("category").notNull(),
    symbol: text("symbol").notNull(),
    direction: text("direction").notNull(),
    payload: text("payload").notNull(),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_hooks_device_identifier").on(table.deviceId, table.identifier),
    index("idx_hooks_timestamp").on(table.timestamp),
    index("idx_hooks_category").on(table.category),
  ],
);
