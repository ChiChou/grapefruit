import Java from "frida-java-bridge";

import { getContext } from "../lib/context.js";

export interface QueryResult {
  columns: string[];
  rows: (string | number | null)[][];
}

export interface ContentValues {
  [key: string]:
    | { type: "string"; value: string }
    | { type: "integer"; value: number }
    | { type: "long"; value: number }
    | { type: "float"; value: number }
    | { type: "double"; value: number }
    | { type: "boolean"; value: boolean }
    | { type: "short"; value: number };
}

export interface QueryOptions {
  projection?: string[];
  selection?: string;
  selectionArgs?: string[];
  sortOrder?: string;
}

export function query(uri: string, options?: QueryOptions) {
  return new Promise<QueryResult>((resolve, reject) => {
    Java.perform(() => {
      try {
        const Uri = Java.use("android.net.Uri");

        const cr = getContext().getContentResolver();
        const contentUri = Uri.parse(uri);

        const projection = options?.projection
          ? Java.array("java.lang.String", options.projection)
          : null;

        const selectionArgs = options?.selectionArgs
          ? Java.array("java.lang.String", options.selectionArgs)
          : null;

        const cursor = cr.query(
          contentUri,
          projection,
          options?.selection || null,
          selectionArgs,
          options?.sortOrder || null,
        );

        if (!cursor) {
          resolve({ columns: [], rows: [] });
          return;
        }

        const columnNames = cursor.getColumnNames();
        const columns: string[] = [];
        for (let i = 0; i < columnNames.length; i++) {
          columns.push(columnNames[i]);
        }

        const rows: (string | number | null)[][] = [];
        const LIMIT = 500;
        let count = 0;

        while (cursor.moveToNext() && count < LIMIT) {
          const row: (string | number | null)[] = [];
          for (let col = 0; col < columns.length; col++) {
            const type = cursor.getType(col);
            switch (type) {
              case 0: // NULL
                row.push(null);
                break;
              case 1: // INTEGER
                row.push(cursor.getLong(col));
                break;
              case 2: // FLOAT
                row.push(cursor.getDouble(col));
                break;
              case 3: // STRING
                row.push(cursor.getString(col));
                break;
              case 4: // BLOB
                row.push("[blob]");
                break;
              default:
                row.push(cursor.getString(col));
            }
          }
          rows.push(row);
          count++;
        }

        cursor.close();
        resolve({ columns, rows });
      } catch (e) {
        reject(e);
      }
    });
  });
}

function buildContentValues(values: ContentValues): Java.Wrapper {
  const ContentValues = Java.use("android.content.ContentValues");
  const cv = ContentValues.$new();

  for (const [key, entry] of Object.entries(values)) {
    switch (entry.type) {
      case "string":
        cv.put(
          key,
          Java.use("java.lang.String").$new(entry.value as string),
        );
        break;
      case "integer":
        cv.put(
          key,
          Java.use("java.lang.Integer").$new(entry.value as number),
        );
        break;
      case "long":
        cv.put(
          key,
          Java.use("java.lang.Long").$new(entry.value as number),
        );
        break;
      case "float":
        cv.put(
          key,
          Java.use("java.lang.Float").$new(entry.value as number),
        );
        break;
      case "double":
        cv.put(
          key,
          Java.use("java.lang.Double").$new(entry.value as number),
        );
        break;
      case "boolean":
        cv.put(
          key,
          Java.use("java.lang.Boolean").$new(entry.value as boolean),
        );
        break;
      case "short":
        cv.put(
          key,
          Java.use("java.lang.Short").$new(entry.value as number),
        );
        break;
    }
  }

  return cv;
}

export function insert(uri: string, values: ContentValues) {
  return new Promise<string | null>((resolve, reject) => {
    Java.perform(() => {
      try {
        const Uri = Java.use("android.net.Uri");
        const cr = getContext().getContentResolver();
        const result = cr.insert(Uri.parse(uri), buildContentValues(values));
        resolve(result ? result.toString() : null);
      } catch (e) {
        reject(e);
      }
    });
  });
}

export function update(
  uri: string,
  values: ContentValues,
  selection?: string,
  selectionArgs?: string[],
) {
  return new Promise<number>((resolve, reject) => {
    Java.perform(() => {
      try {
        const Uri = Java.use("android.net.Uri");
        const cr = getContext().getContentResolver();

        const args = selectionArgs
          ? Java.array("java.lang.String", selectionArgs)
          : null;

        const count: number = cr.update(
          Uri.parse(uri),
          buildContentValues(values),
          selection || null,
          args,
        );
        resolve(count);
      } catch (e) {
        reject(e);
      }
    });
  });
}

export function del(uri: string, selection?: string, selectionArgs?: string[]) {
  return new Promise<number>((resolve, reject) => {
    Java.perform(() => {
      try {
        const Uri = Java.use("android.net.Uri");
        const cr = getContext().getContentResolver();

        const args = selectionArgs
          ? Java.array("java.lang.String", selectionArgs)
          : null;

        const count: number = cr.delete(
          Uri.parse(uri),
          selection || null,
          args,
        );
        resolve(count);
      } catch (e) {
        reject(e);
      }
    });
  });
}
