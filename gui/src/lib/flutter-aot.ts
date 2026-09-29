import * as r2 from "./r2/client";

export interface FlutterHeader {
  error?: string;
  kind?: number;
  hash?: string;
  dart_version?: string;
  version_source?: string;
  cws?: number;
  tag_style?: string;
  vm_data?: number;
  vm_instr?: number;
  iso_data?: number;
  iso_instr?: number;
  single_snapshot?: boolean;
  container?: {
    kind?: string;
    note_owner?: string;
    payload_offset?: number;
    payload_size?: number;
    macho_offset?: number;
  };
  [key: string]: unknown;
}

export interface FlutterFunction {
  addr: number;
  name: string;
  size?: number;
  signature?: string;
}

export interface FlutterField {
  name?: string;
  type?: string;
  offset?: number;
  flags?: Record<string, boolean>;
}

export interface FlutterMethod {
  name?: string;
  entry?: number;
  owner?: string;
  signature?: string;
  kind?: string;
  kind_tag?: number;
}

export interface FlutterClass {
  ref: number;
  class_id?: number;
  name?: string;
  library?: { ref?: number; name?: string };
  super?: { ref?: number; type_ref?: number; name?: string };
  interfaces?: Array<{ ref?: number; class_ref?: number; name?: string }>;
  layout?: {
    instance_size?: number;
    next_field_offset?: number;
    type_params?: number;
    type_arg_offset?: number;
    field_bitmap?: number;
  };
  flags?: Record<string, boolean>;
  fields?: FlutterField[];
  methods?: FlutterMethod[];
}

export interface FlutterStringRef {
  obj?: number;
  type?: string;
  kind?: string;
  name?: string;
}

export interface FlutterString {
  ref: number;
  len: number;
  value?: string;
  category?: string;
  two_byte?: boolean;
  canonical?: boolean;
  addr?: number;
  refs?: FlutterStringRef[];
}

export interface FlutterXrefNode {
  type: string;
  name?: string;
  ref?: number;
  addr?: number;
}

export interface FlutterXref {
  kind: string;
  origin: string;
  src: FlutterXrefNode;
  dst: FlutterXrefNode;
}

export interface FlutterComponent {
  type: string;
  name: string;
  version: string | null;
  confidence: number;
  occurrences: number;
  source?: string;
  evidence?: string;
}

export interface FlutterSbom {
  format: string;
  complete: boolean;
  note?: string;
  input?: string;
  snapshot?: {
    hash?: string;
    dart_version?: string;
    vm_data?: number;
    iso_data?: number;
  };
  count?: number;
  components?: FlutterComponent[];
  omitted?: number;
}

export interface FlutterAnalysis {
  header: FlutterHeader;
  functions: FlutterFunction[];
  classes: FlutterClass[];
  strings: FlutterString[];
  xrefs: FlutterXref[];
  sbom: FlutterSbom;
}

export interface FlutterOptions {
  fuzzyStrings?: boolean;
  namePool?: boolean;
  limit?: number;
}

function parse<T>(text: string, fallback: T): T {
  if (!text.trim()) return fallback;
  const value = JSON.parse(text) as T | { error?: unknown };
  if (value && typeof value === "object" && "error" in value && value.error) {
    throw new Error(String(value.error));
  }
  return value as T;
}

function suffix(opts: FlutterOptions) {
  if (!opts.limit) return "";
  const limit = Math.max(1, Math.min(100_000, Math.trunc(opts.limit)));
  return ` -l ${limit}`;
}

async function json<T>(action: string, fallback: T, opts: FlutterOptions) {
  const out = await r2.cmd(`r2flutter -q -j${action}${suffix(opts)}`);
  return parse(out, fallback);
}

export async function analyze(
  name: string,
  data: ArrayBuffer,
  opts: FlutterOptions = {},
): Promise<FlutterAnalysis> {
  await r2.init();
  await r2.loadFile(name, data.slice(0), { analyze: false });
  await r2.cmd(`e r2flutter.namepool=${opts.namePool ? "true" : "false"}`);

  const header = await json<FlutterHeader>("H", {}, opts);
  const functions = await json<FlutterFunction[]>("f", [], opts);
  const classes = await json<FlutterClass[]>("c", [], opts);
  const strings = await json<FlutterString[]>(opts.fuzzyStrings ? "zz" : "z", [], opts);
  const xrefs = await json<FlutterXref[]>("x", [], opts);
  const sbom = await json<FlutterSbom>("S", { format: "", complete: false }, opts);

  return { header, functions, classes, strings, xrefs, sbom };
}

export async function disassemble(addr: number, count = 48) {
  if (!Number.isSafeInteger(addr) || addr < 0) throw new Error("Invalid address");
  const lines = Math.max(1, Math.min(500, Math.trunc(count)));
  return r2.cmd(`pd ${lines} @ 0x${addr.toString(16)}`);
}
