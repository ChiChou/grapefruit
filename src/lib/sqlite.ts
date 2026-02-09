/**
 * SQLite driver abstraction layer for Bun and Node.js compatibility
 */

export interface RunResult {
  changes: number;
  lastInsertRowid: number | bigint;
}

export interface Statement {
  run(...params: unknown[]): RunResult;
  get(...params: unknown[]): Record<string, unknown> | undefined;
  all(...params: unknown[]): Record<string, unknown>[];
}

export interface Database {
  exec(sql: string): void;
  prepare(sql: string): Statement;
  close(): void;
}

type SqliteValue = string | number | bigint | Buffer | null;

type DatabaseFactory = (path: string) => Database;

let createDatabase: DatabaseFactory;

// Try Bun sqlite first, fall back to Node.js
try {
  const { Database: BunDatabase } = await import("bun:sqlite");

  createDatabase = (path: string): Database => {
    const db = new BunDatabase(path);
    return {
      exec: (sql: string) => db.run(sql),
      prepare: (sql: string) => {
        const stmt = db.prepare(sql);
        return {
          run: (...params: SqliteValue[]) => {
            const result = stmt.run(...params);
            return {
              changes: result.changes,
              lastInsertRowid: result.lastInsertRowid,
            };
          },
          get: (...params: SqliteValue[]) =>
            stmt.get(...params) as Record<string, unknown> | undefined,
          all: (...params: SqliteValue[]) =>
            stmt.all(...params) as Record<string, unknown>[],
        };
      },
      close: () => db.close(),
    };
  };
} catch {
  // Bun not available, use Node.js sqlite
  const { DatabaseSync } = await import("node:sqlite");

  createDatabase = (path: string): Database => {
    const db = new DatabaseSync(path, { open: true });
    return {
      exec: (sql: string) => db.exec(sql),
      prepare: (sql: string) => {
        const stmt = db.prepare(sql);
        return {
          run: (...params: SqliteValue[]) => {
            const result = stmt.run(...params);
            return {
              changes: result.changes as number,
              lastInsertRowid: result.lastInsertRowid as number | bigint,
            };
          },
          get: (...params: SqliteValue[]) =>
            stmt.get(...params) as Record<string, unknown> | undefined,
          all: (...params: SqliteValue[]) =>
            stmt.all(...params) as Record<string, unknown>[],
        };
      },
      close: () => db.close(),
    };
  };
}

export { createDatabase };
