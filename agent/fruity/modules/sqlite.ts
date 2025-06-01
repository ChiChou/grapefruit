import uuid from '../lib/uuid.js'

function quote(table: string) {
  return `"${table.replace(/"/g, '')}"`
}

function * all(statement: SqliteStatement) {
  let row
  /* eslint no-cond-assign: 0 */
  while ((row = statement.step()) !== null) yield row
}

export class Database {
  private db: SqliteDatabase

  constructor(filename: string) {
    this.db = SqliteDatabase.open(filename)
  }

  tables() {
    const SQL_TABLES = 'SELECT tbl_name FROM sqlite_master WHERE type="table" and tbl_name <> "sqlite_sequence"'
    const statement = this.prepare(SQL_TABLES)
    return [...all(statement)].map(row => row[0])
  }

  columns(table: string) {
    // I know it's an injection, but since this tool allows you query arbitary sql,
    // leave this alone or help me commit some code to escape the table name

    const statement = this.prepare(`PRAGMA table_info(${quote(table)})`)
    return [...all(statement)].map((info: any[6]) => info.slice(1, 3))
  }

  prepare(sql: string, args: any[] = []) {
    const statement = this.db.prepare(sql)
    for (let i = 0; i < args.length; i++) {
      const index = i + 1
      const arg = args[i]
      if (typeof arg === 'number') {
        if (Math.floor(arg) === arg)
          statement.bindInteger(index, arg)
        else
          statement.bindFloat(index, arg)
      } else if (arg === null || typeof arg === 'undefined') {
        statement.bindNull(index)
      } else if (arg instanceof ArrayBuffer) {
        statement.bindBlob(index, arg)
      } else {
        statement.bindText(index, arg)
      }
    }
    return statement
  }

  close() {
    return this.db.close()
  }
}

const handles = new Map<string, Database>()

export function open(path: string) {
  const id = uuid()
  const db = new Database(path)
  handles.set(id, db)
  return id
}

export function query(id: string, sql: string) {
  const db = handles.get(id)
  if (!db) throw new Error(`invalid handle ${id}`)
  return [...all(db.prepare(sql))]
}

export function close(id: string) {
  const db = handles.get(id)
  if (!db) throw new Error(`invalid handle ${id}`)
  db.close()
  handles.delete(id)
}

export function dump(path: string, table: string) {
  const db = new Database(path)
  const sql = `select * from ${quote(table)} limit 500`
  const result = {
    header: db.columns(table),
    data: [...all(db.prepare(sql))]
  }
  db.close()
  return result
}

export function tables(path: string) {
  const db = new Database(path)
  const list = db.tables()
  db.close()
  return list
}
