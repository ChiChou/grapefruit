function quote(table: string) {
  return `"${table.replace(/"/g, "")}"`;
}

function convertArrayBuffer(item: unknown) {
  if (item instanceof ArrayBuffer) {
    const view = new Uint8Array(item);
    const maxBytes = 12;
    const hexParts: string[] = [];
    const count = Math.min(view.length, maxBytes);

    for (let i = 0; i < count; i++) {
      hexParts.push(view[i].toString(16).padStart(2, "0"));
    }

    const suffix = view.length > maxBytes ? "…" : "";
    return `X'${hexParts.join("")}${suffix}'`;
  }

  return item;
}

function* all(statement: SqliteStatement) {
  let row;
  /* eslint no-cond-assign: 0 */
  while ((row = statement.step()) !== null) yield row.map(convertArrayBuffer);
}

export interface ColumnInfo {
  name: string;
  type: string;
  // notNull: string;
}

class Database {
  private db: SqliteDatabase;

  constructor(filename: string) {
    this.db = SqliteDatabase.open(filename);
  }

  tables() {
    const SQL_TABLES =
      'SELECT tbl_name FROM sqlite_master WHERE type="table" and tbl_name <> "sqlite_sequence"';
    const statement = this.prepare(SQL_TABLES);
    return [...all(statement)].map((row) => row[0] as string);
  }

  columns(table: string): ColumnInfo[] {
    type TableInfo = [
      cid: number,
      name: string,
      type: string,
      notNull: boolean,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      defaultValue: any,
      pk: boolean,
    ];

    const statement = this.prepare(`PRAGMA table_info(${quote(table)})`);
    return [...(all(statement) as Generator<TableInfo>)].map((r) => {
      return { name: r[1], type: r[2] };
    });
  }

  prepare(sql: string, args: unknown[] = []) {
    const statement = this.db.prepare(sql);
    for (let i = 0; i < args.length; i++) {
      const index = i + 1;
      const arg = args[i];
      if (typeof arg === "number") {
        if (Math.floor(arg) === arg) statement.bindInteger(index, arg);
        else statement.bindFloat(index, arg);
      } else if (arg === null || typeof arg === "undefined") {
        statement.bindNull(index);
      } else if (arg instanceof ArrayBuffer) {
        statement.bindBlob(index, arg);
      } else {
        statement.bindText(index, `${arg}`);
      }
    }
    return statement;
  }

  close() {
    this.db.close();
  }
}

export interface DumpResult {
  header: ColumnInfo[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[];
}

export interface QueryResult {
  columns: string[];
  types: string[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: any[];
}

export function dump(path: string, table: string) {
  const db = new Database(path);
  const sql = `select * from ${quote(table)} limit 500`;
  const result = {
    header: db.columns(table),
    data: [...all(db.prepare(sql))],
  };

  db.close();
  return result;
}

export function query(path: string, sql: string) {
  const db = new Database(path);
  const statement = db.prepare(sql);

  const rows = [...all(statement)];

  // Use new columnNames/columnTypes APIs with typeof fallback
  const firstRow = rows[0];
  const fallbackLen = firstRow ? firstRow.length : 0;

  const columns: string[] =
    typeof statement.columnNames !== "undefined"
      ? [...statement.columnNames]
      : Array.from({ length: fallbackLen }, (_, i) => `col${i}`);

  const types: string[] =
    typeof statement.declaredTypes !== "undefined"
      ? statement.declaredTypes.map((t) => t ?? "")
      : Array.from({ length: fallbackLen }, () => "");

  db.close();
  return { columns, types, data: rows } satisfies QueryResult;
}

export function tables(path: string) {
  const db = new Database(path);
  const list = db.tables();
  db.close();
  return list;
}
