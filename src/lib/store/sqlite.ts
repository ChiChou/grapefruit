import {
  type DatabaseSync,
  type SQLInputValue,
  type StatementResultingChanges,
  type StatementSync,
} from "node:sqlite";

import { entityKind } from "drizzle-orm/entity";
import { DefaultLogger, NoopLogger, type Logger } from "drizzle-orm/logger";
import { readMigrationFiles, type MigrationConfig } from "drizzle-orm/migrator";
import {
  createTableRelationsHelpers,
  extractTablesRelationalConfig,
  type RelationalSchemaConfig,
  type TablesRelationalConfig,
} from "drizzle-orm/relations";
import { fillPlaceholders, sql, type Query } from "drizzle-orm/sql/sql";
import {
  BaseSQLiteDatabase,
  SQLiteSyncDialect,
  SQLiteTransaction,
} from "drizzle-orm/sqlite-core";
import type { SelectedFieldsOrdered } from "drizzle-orm/sqlite-core/query-builders/select.types";
import {
  type PreparedQueryConfig as PreparedQueryConfigBase,
  type SQLiteExecuteMethod,
  SQLitePreparedQuery as PreparedQueryBase,
  SQLiteSession,
  type SQLiteTransactionConfig,
} from "drizzle-orm/sqlite-core/session";
import * as drizzleUtils from "drizzle-orm/utils";
import type { DrizzleConfig } from "drizzle-orm/utils";

type PreparedQueryConfig = Omit<PreparedQueryConfigBase, "statement" | "run">;
const mapResultRow = Reflect.get(drizzleUtils, "mapResultRow") as (
  fields: SelectedFieldsOrdered,
  row: unknown[],
  joins?: Record<string, boolean>,
) => unknown;

export class NodeSQLiteDatabase<
  TSchema extends Record<string, unknown> = Record<string, never>,
> extends BaseSQLiteDatabase<"sync", StatementResultingChanges, TSchema> {
  static readonly [entityKind] = "NodeSQLiteDatabase";
}

class NodeSQLiteSession<
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
> extends SQLiteSession<
  "sync",
  StatementResultingChanges,
  TFullSchema,
  TSchema
> {
  static readonly [entityKind] = "NodeSQLiteSession";

  private client: DatabaseSync;
  private dialectValue: SQLiteSyncDialect;
  private logger: Logger;
  private schema: RelationalSchemaConfig<TSchema> | undefined;

  constructor(
    client: DatabaseSync,
    dialect: SQLiteSyncDialect,
    schema: RelationalSchemaConfig<TSchema> | undefined,
    logger: Logger = new NoopLogger(),
  ) {
    super(dialect);
    this.client = client;
    this.dialectValue = dialect;
    this.logger = logger;
    this.schema = schema;
  }

  prepareQuery<T extends Omit<PreparedQueryConfig, "run">>(
    query: Query,
    fields: SelectedFieldsOrdered | undefined,
    executeMethod: SQLiteExecuteMethod,
    isResponseInArrayMode: boolean,
    customResultMapper?: (rows: unknown[][]) => unknown,
  ): NodePreparedQuery<T> {
    return new NodePreparedQuery(
      this.client.prepare(query.sql),
      query,
      this.logger,
      fields,
      executeMethod,
      isResponseInArrayMode,
      customResultMapper,
    );
  }

  transaction<T>(
    transaction: (tx: NodeSQLiteTransaction<TFullSchema, TSchema>) => T,
    config: SQLiteTransactionConfig = {},
  ): T {
    const tx = new NodeSQLiteTransaction(
      "sync",
      this.dialectValue,
      this,
      this.schema,
    );
    this.client.exec(`begin ${config.behavior ?? "deferred"}`);
    try {
      const result = transaction(tx);
      this.client.exec("commit");
      return result;
    } catch (error) {
      this.client.exec("rollback");
      throw error;
    }
  }
}

class NodeSQLiteTransaction<
  TFullSchema extends Record<string, unknown>,
  TSchema extends TablesRelationalConfig,
> extends SQLiteTransaction<
  "sync",
  StatementResultingChanges,
  TFullSchema,
  TSchema
> {
  static readonly [entityKind] = "NodeSQLiteTransaction";

  private dialectValue: SQLiteSyncDialect;
  private sessionValue: NodeSQLiteSession<TFullSchema, TSchema>;

  constructor(
    resultType: "sync",
    dialect: SQLiteSyncDialect,
    session: NodeSQLiteSession<TFullSchema, TSchema>,
    schema: RelationalSchemaConfig<TSchema> | undefined,
    nestedIndex = 0,
  ) {
    super(resultType, dialect, session, schema, nestedIndex);
    this.dialectValue = dialect;
    this.sessionValue = session;
  }

  transaction<T>(
    transaction: (tx: NodeSQLiteTransaction<TFullSchema, TSchema>) => T,
  ): T {
    const name = `sp${this.nestedIndex}`;
    const tx = new NodeSQLiteTransaction<TFullSchema, TSchema>(
      "sync",
      this.dialectValue,
      this.sessionValue,
      this.schema,
      this.nestedIndex + 1,
    );
    this.sessionValue.run(sql.raw(`savepoint ${name}`));
    try {
      const result = transaction(tx);
      this.sessionValue.run(sql.raw(`release savepoint ${name}`));
      return result;
    } catch (error) {
      this.sessionValue.run(sql.raw(`rollback to savepoint ${name}`));
      throw error;
    }
  }
}

class NodePreparedQuery<
  T extends PreparedQueryConfig = PreparedQueryConfig,
> extends PreparedQueryBase<{
  type: "sync";
  run: StatementResultingChanges;
  all: T["all"];
  get: T["get"];
  values: T["values"];
  execute: T["execute"];
}> {
  static readonly [entityKind] = "NodeSQLitePreparedQuery";

  private stmt: StatementSync;
  private logger: Logger;
  private fields: SelectedFieldsOrdered | undefined;
  private arrayMode: boolean;
  private customResultMapper?: (rows: unknown[][]) => unknown;
  joinsNotNullableMap?: Record<string, boolean>;

  constructor(
    stmt: StatementSync,
    query: Query,
    logger: Logger,
    fields: SelectedFieldsOrdered | undefined,
    executeMethod: SQLiteExecuteMethod,
    arrayMode: boolean,
    customResultMapper?: (rows: unknown[][]) => unknown,
  ) {
    super("sync", executeMethod, query);
    this.stmt = stmt;
    this.logger = logger;
    this.fields = fields;
    this.arrayMode = arrayMode;
    this.customResultMapper = customResultMapper;
  }

  private params(values?: Record<string, unknown>): SQLInputValue[] {
    return fillPlaceholders(this.query.params, values ?? {}) as SQLInputValue[];
  }

  private returnArrays(enabled: boolean): boolean {
    const fn = Reflect.get(this.stmt, "setReturnArrays");
    if (typeof fn !== "function") return false;
    Reflect.apply(fn, this.stmt, [enabled]);
    return true;
  }

  private rows(params: SQLInputValue[]): unknown[][] {
    if (this.returnArrays(true)) {
      return this.stmt.all(...params) as unknown as unknown[][];
    }
    return this.stmt.all(...params).map((row) => Object.values(row));
  }

  private row(params: SQLInputValue[]): unknown[] | undefined {
    if (this.returnArrays(true)) {
      return this.stmt.get(...params) as unknown as unknown[] | undefined;
    }
    const row = this.stmt.get(...params);
    return row ? Object.values(row) : undefined;
  }

  run(values?: Record<string, unknown>): StatementResultingChanges {
    const params = this.params(values);
    this.logger.logQuery(this.query.sql, params);
    return this.stmt.run(...params);
  }

  all(values?: Record<string, unknown>): T["all"] {
    const params = this.params(values);
    this.logger.logQuery(this.query.sql, params);
    if (!this.fields && !this.customResultMapper) {
      this.returnArrays(false);
      return this.stmt.all(...params) as T["all"];
    }

    const rows = this.rows(params);
    if (this.customResultMapper) {
      return this.customResultMapper(rows) as T["all"];
    }
    return rows.map((row) =>
      mapResultRow(this.fields!, row, this.joinsNotNullableMap),
    ) as T["all"];
  }

  get(values?: Record<string, unknown>): T["get"] {
    const params = this.params(values);
    this.logger.logQuery(this.query.sql, params);
    if (!this.fields && !this.customResultMapper) {
      this.returnArrays(false);
      return this.stmt.get(...params) as T["get"];
    }

    const row = this.row(params);
    if (!row) return undefined as T["get"];
    if (this.customResultMapper) {
      return this.customResultMapper([row]) as T["get"];
    }
    return mapResultRow(
      this.fields!,
      row,
      this.joinsNotNullableMap,
    ) as T["get"];
  }

  values(values?: Record<string, unknown>): T["values"] {
    const params = this.params(values);
    this.logger.logQuery(this.query.sql, params);
    return this.rows(params) as T["values"];
  }

  isResponseInArrayMode(): boolean {
    return this.arrayMode;
  }
}

export type NodeSQLiteDb<
  TSchema extends Record<string, unknown> = Record<string, never>,
> = NodeSQLiteDatabase<TSchema> & { $client: DatabaseSync };

export function drizzle<TSchema extends Record<string, unknown>>(
  client: DatabaseSync,
  config: DrizzleConfig<TSchema> = {},
): NodeSQLiteDb<TSchema> {
  const dialect = new SQLiteSyncDialect({ casing: config.casing });
  const logger =
    config.logger === true
      ? new DefaultLogger()
      : config.logger === false
        ? new NoopLogger()
        : config.logger;

  let relational: RelationalSchemaConfig<TablesRelationalConfig> | undefined;
  if (config.schema) {
    const tables = extractTablesRelationalConfig(
      config.schema,
      createTableRelationsHelpers,
    );
    relational = {
      fullSchema: config.schema,
      schema: tables.tables,
      tableNamesMap: tables.tableNamesMap,
    };
  }

  const session = new NodeSQLiteSession(
    client,
    dialect,
    relational,
    logger,
  );
  const db = new NodeSQLiteDatabase(
    "sync",
    dialect,
    session,
    relational,
  );
  return Object.assign(db, { $client: client }) as NodeSQLiteDb<TSchema>;
}

export function migrate<TSchema extends Record<string, unknown>>(
  db: NodeSQLiteDb<TSchema>,
  config: MigrationConfig,
): void {
  const internal = db as unknown as {
    dialect: SQLiteSyncDialect;
    session: SQLiteSession<
      "sync",
      unknown,
      Record<string, unknown>,
      TablesRelationalConfig
    >;
  };
  internal.dialect.migrate(
    readMigrationFiles(config),
    internal.session,
    config,
  );
}
