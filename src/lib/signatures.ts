import { DatabaseSync } from "node:sqlite";

export type FridaType = string | FridaType[];

export interface NativeType {
  c: string;
  canonical: string;
  frida: FridaType;
  size: number | null;
  display: string;
  approximate: boolean;
}

export interface Query {
  platform: "android" | "darwin";
  name: string;
  module?: string;
  arch?: string;
}

export function moduleName(path: string, platform: Query["platform"]): string {
  const name = path.split("/").at(-1) ?? path;
  if (platform === "android") return name;
  if (/^libsystem_|^libSystem[.]/i.test(name)) return "libSystem";
  return name.replace(/(?:\.(?:\d+|[A-Z]))*\.dylib$/, "");
}

export function architecture(arch: string): string {
  return ({ x86: "ia32", x86_64: "x64", aarch64: "arm64", arm64e: "arm64", thumb: "arm" } as Record<string, string>)[arch] ?? arch;
}

export class Catalog {
  private db: DatabaseSync;
  readonly version: string;

  constructor(path: string, version?: string) {
    this.db = new DatabaseSync(path, { readOnly: true, allowExtension: false });
    try {
      this.db.exec("PRAGMA query_only = ON; PRAGMA trusted_schema = OFF");
      const schema = this.db.prepare("PRAGMA user_version").get() as { user_version: number };
      if (schema.user_version !== 1) throw new Error("Unsupported signature database schema");
      const row = this.db.prepare("SELECT value FROM metadata WHERE key = 'version'").get() as { value: string } | undefined;
      if (!row || (version && row.value !== version)) throw new Error("Signature database version does not match the pinned release");
      this.version = row.value;
    } catch (error) {
      this.db.close();
      throw error;
    }
  }

  close() { this.db.close(); }

  private type(id: number): NativeType {
    const row = this.db.prepare("SELECT * FROM types WHERE id = ?").get(id) as {
      c_spelling: string; canonical_c: string; frida_type: string;
      size: number | null; display_hint: string; approximate: number;
    };
    return { c: row.c_spelling, canonical: row.canonical_c, frida: JSON.parse(row.frida_type), size: row.size, display: row.display_hint, approximate: !!row.approximate };
  }

  lookup(query: Query) {
    const arch = query.arch ? architecture(query.arch) : null;
    const module = moduleName(query.module ?? "", query.platform);
    let symbol = query.name.replace(/@{1,2}[^@]+$/, "");
    const select = (name: string) => this.db.prepare(`
      SELECT f.*, s.sdk, s.version AS sdk_version, s.revision
      FROM functions f JOIN sources s ON s.id = f.source_id
      WHERE f.platform = ? AND f.symbol = ? AND f.kind = 'function'
        AND (? IS NULL OR f.arch = ?)
      ORDER BY (f.module = ?) DESC,
        CASE s.sdk WHEN 'NDK' THEN 0 WHEN 'iphoneos' THEN 0 WHEN 'macosx' THEN 1 ELSE 2 END,
        f.arch = 'arm64' DESC, f.id
      LIMIT 1
    `).get(query.platform, name, arch, arch, module) as {
      id: number; module: string; symbol: string; arch: string; return_type_id: number;
      variadic: number; header: string; sdk: string; sdk_version: string; revision: string;
    } | undefined;
    let row = select(symbol);
    if (!row && query.platform === "darwin" && symbol.startsWith("_")) {
      symbol = symbol.slice(1);
      row = select(symbol);
    }
    if (!row) return null;
    const params = this.db.prepare("SELECT name, type_id FROM parameters WHERE function_id = ? ORDER BY position").all(row.id) as { name: string; type_id: number }[];
    return {
      module: row.module, symbol: row.symbol, arch: row.arch,
      args: params.map((arg) => ({ ...this.type(arg.type_id), name: arg.name })),
      returns: this.type(row.return_type_id), variadic: !!row.variadic,
      source: `${row.sdk} ${row.sdk_version}`, revision: row.revision, header: row.header,
      nameOnly: !!module && module !== row.module,
    };
  }
}
