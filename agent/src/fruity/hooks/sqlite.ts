import { BaseMessage, bt } from "./context.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "sql";
  filename?: string;
  sql?: string;

  bindIndex?: number;
  bindValue?: number | string | null;
}

export function open() {
  const sqlite = Process.findModuleByName("libsqlite3.dylib");
  if (!sqlite) return [];

  const hooks: InvocationListener[] = [];

  const open = sqlite.getExportByName("sqlite3_open");
  if (open) {
    hooks.push(
      Interceptor.attach(open, {
        onEnter(args) {
          const filename = args[0].readUtf8String() || "unknown";
          send({
            subject: "hook",
            category: "sql",
            symbol: "sqlite3_open",
            dir: "enter",
            filename,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  const open16 = sqlite.getExportByName("sqlite3_open16");
  if (open16) {
    hooks.push(
      Interceptor.attach(open16, {
        onEnter(args) {
          const filename = args[0].readUtf16String() || "unknown";
          send({
            subject: "hook",
            category: "sql",
            symbol: "sqlite3_open16",
            dir: "enter",
            filename,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  const open_v2 = sqlite.getExportByName("sqlite3_open_v2");
  if (open_v2) {
    hooks.push(
      Interceptor.attach(open_v2, {
        onEnter(args) {
          const filename = args[0].readUtf8String() || "unknown";
          send({
            subject: "hook",
            category: "sql",
            symbol: "sqlite3_open_v2",
            dir: "enter",
            filename,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }
}

export function prepare() {
  const sqlite = Process.findModuleByName("libsqlite3.dylib");
  if (!sqlite) return [];

  const hooks: InvocationListener[] = [];

  const prepare = sqlite.getExportByName("sqlite3_prepare");
  if (prepare) {
    hooks.push(
      Interceptor.attach(prepare, {
        onEnter(args) {
          const sql = args[1].readUtf8String() || "unknown";
          send({
            subject: "hook",
            category: "sql",
            symbol: "sqlite3_prepare",
            dir: "enter",
            backtrace: bt(this.context),
            sql,
          } as Message);
        },
      }),
    );
  }

  const prepare_v2 = sqlite.getExportByName("sqlite3_prepare_v2");
  if (prepare_v2) {
    hooks.push(
      Interceptor.attach(prepare_v2, {
        onEnter(args) {
          const sql = args[1].readUtf8String() || "unknown";
          send({
            subject: "hook",
            category: "sql",
            symbol: "sqlite3_prepare_v2",
            dir: "enter",
            backtrace: bt(this.context),
            sql,
          } as Message);
        },
      }),
    );
  }

  const prepare_v3 = sqlite.getExportByName("sqlite3_prepare_v3");
  if (prepare_v3) {
    hooks.push(
      Interceptor.attach(prepare_v3, {
        onEnter(args) {
          const sql = args[1].readUtf8String() || "unknown";
          send({
            subject: "hook",
            category: "sql",
            symbol: "sqlite3_prepare_v3",
            dir: "enter",
            backtrace: bt(this.context),
            sql,
          } as Message);
        },
      }),
    );
  }

  return hooks;
}

type SQLiteValue = string | number | null;

export function bind() {
  const sqlite = Process.findModuleByName("libsqlite3.dylib");
  if (!sqlite) return [];

  const hooks: InvocationListener[] = [];
  const sqlite3_sql = new NativeFunction(
    sqlite.getExportByName("sqlite3_sql"),
    "pointer",
    ["pointer"],
  );

  const valueGetters: Record<string, (args: NativePointer[]) => SQLiteValue> = {
    int: (args) => args[2].toInt32(),
    int64: (args) => args[2].toString(),
    double: (args) => args[2] as unknown as number,
    text: (args) => args[2].readUtf8String(),
    text64: (args) => args[2].readUtf8String(),
    text16: (args) => args[2].readUtf16String(),
    blob: (args) => `[Blob size=${args[3].toInt32()}]`,
    blob64: (args) => `[Blob size=${args[3].toString()}]`,
    null: () => "NULL",
    zeroblob: (args) => `[Zeroblob size=${args[2].toInt32()}]`,
    zeroblob64: (args) => `[Zeroblob size=${args[2].toString()}]`,
    value: () => "[sqlite3_value]",
    pointer: () => "[pointer]",
  };

  for (const [type, getter] of Object.entries(valueGetters)) {
    const funcName = `sqlite3_bind_${type}`;
    const func = sqlite.findExportByName(funcName);
    if (!func) continue;

    hooks.push(
      Interceptor.attach(func, {
        onEnter(args) {
          const stmtPtr = args[0];
          let sql = "";

          if (!stmtPtr.isNull()) {
            const sqlPtr = sqlite3_sql(stmtPtr) as NativePointer;
            if (!sqlPtr.isNull()) {
              sql = sqlPtr.readUtf8String() || "";
            }
          }

          let value: SQLiteValue;
          try {
            value = getter(args);
          } catch (e) {
            value = "[Error reading value]";
          }

          send({
            subject: "hook",
            category: "sql",
            symbol: funcName,
            dir: "enter",
            backtrace: bt(this.context),
            sql: sql,
            bindIndex: args[1].toInt32(),
            bindValue: value,
          } as Message);
        },
      }),
    );
  }

  return hooks;
}
