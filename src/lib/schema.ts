import { sql } from "drizzle-orm";
import {
  sqliteTable,
  text,
  integer,
  blob,
  index,
  uniqueIndex,
} from "drizzle-orm/sqlite-core";

export const preferences = sqliteTable("preferences", {
  key: text("key").primaryKey(),
  value: text("value"),
});

export const nsurlRequests = sqliteTable(
  "nsurl_requests",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    requestId: text("request_id").notNull(),
    data: text("data").notNull(),
    attachment: text("attachment"),
    mime: text("mime"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_nsurl_requests_device_identifier").on(
      table.deviceId,
      table.identifier,
    ),
    uniqueIndex("idx_nsurl_requests_request_id").on(
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
    line: text("line"),
    extra: text("extra"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_hooks_device_identifier").on(table.deviceId, table.identifier),
    index("idx_hooks_timestamp").on(table.timestamp),
    index("idx_hooks_category").on(table.category),
  ],
);

export const flutter = sqliteTable(
  "flutter",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    timestamp: text("timestamp").notNull(),
    type: text("type").notNull(),
    direction: text("direction").notNull(),
    channel: text("channel").notNull(),
    data: text("data"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_flutter_device_identifier").on(table.deviceId, table.identifier),
    index("idx_flutter_timestamp").on(table.timestamp),
  ],
);

export const jni = sqliteTable(
  "jni",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    timestamp: text("timestamp").notNull(),
    type: text("type").notNull(),
    method: text("method").notNull(),
    callType: text("call_type").notNull(),
    threadId: integer("thread_id"),
    args: text("args"),
    ret: text("ret"),
    backtrace: text("backtrace"),
    library: text("library"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_jni_device_identifier").on(table.deviceId, table.identifier),
    index("idx_jni_method").on(table.method),
    index("idx_jni_timestamp").on(table.timestamp),
  ],
);

export const xpcLogs = sqliteTable(
  "xpc_logs",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    timestamp: text("timestamp").notNull(),
    protocol: text("protocol").notNull(), // "xpc" | "nsxpc"
    event: text("event").notNull(), // "received" | "sent"
    direction: text("direction").notNull(), // "<" | ">"
    service: text("service"),
    peer: integer("peer"),
    message: text("message").notNull(), // JSON-serialized message
    backtrace: text("backtrace"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_xpc_logs_device_identifier").on(
      table.deviceId,
      table.identifier,
    ),
    index("idx_xpc_logs_timestamp").on(table.timestamp),
    index("idx_xpc_logs_protocol").on(table.protocol),
  ],
);

export const hermes = sqliteTable(
  "hbc",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    url: text("url").notNull(),
    hash: text("hash").notNull(),
    size: integer("size").notNull(),
    data: blob("data", { mode: "buffer" }).notNull(),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_hbc_device_identifier").on(table.deviceId, table.identifier),
    uniqueIndex("idx_hbc_hash").on(table.hash),
    index("idx_hbc_created_at").on(table.createdAt),
  ],
);

export const privacy = sqliteTable(
  "privacy",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    timestamp: text("timestamp").notNull(),
    category: text("category").notNull(),
    severity: text("severity").notNull(),
    symbol: text("symbol").notNull(),
    direction: text("direction").notNull(),
    line: text("line"),
    extra: text("extra"),
    backtrace: text("backtrace"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_privacy_device_identifier").on(table.deviceId, table.identifier),
    index("idx_privacy_timestamp").on(table.timestamp),
    index("idx_privacy_category").on(table.category),
    index("idx_privacy_severity").on(table.severity),
  ],
);

export const httpRequests = sqliteTable(
  "http_requests",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    requestId: text("request_id").notNull(),
    data: text("data").notNull(),
    attachment: text("attachment"),
    mime: text("mime"),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
    updatedAt: text("updated_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_http_requests_device_identifier").on(
      table.deviceId,
      table.identifier,
    ),
    uniqueIndex("idx_http_requests_request_id").on(
      table.deviceId,
      table.identifier,
      table.requestId,
    ),
  ],
);

export const crypto = sqliteTable(
  "crypto",
  {
    id: integer("id").primaryKey({ autoIncrement: true }),
    deviceId: text("device_id").notNull(),
    identifier: text("identifier").notNull(),
    timestamp: text("timestamp").notNull(),
    symbol: text("symbol").notNull(),
    direction: text("direction").notNull(),
    line: text("line"),
    extra: text("extra"),
    backtrace: text("backtrace"),
    data: blob("data", { mode: "buffer" }),
    createdAt: text("created_at").default(sql`CURRENT_TIMESTAMP`),
  },
  (table) => [
    index("idx_crypto_device_identifier").on(table.deviceId, table.identifier),
    index("idx_crypto_timestamp").on(table.timestamp),
  ],
);
