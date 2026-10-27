import { createHash } from "node:crypto";
import { readFile, mkdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { DatabaseSync } from "node:sqlite";
import lock from "../signatures.lock.json" with { type: "json" };

const root = join(import.meta.dirname, "..");
const output = join(root, "signatures", "signatures.db");
const hash = (data: Uint8Array) => createHash("sha256").update(data).digest("hex");

export async function check(file = output) {
  const data = await readFile(file);
  if (hash(data) !== lock.sha256) throw new Error("Signature database checksum mismatch; run npm run fetch:signatures");
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const row = db.prepare("SELECT value FROM metadata WHERE key = 'version'").get() as { value: string } | undefined;
    if (row?.value !== lock.version) throw new Error("Signature database version mismatch");
    const schema = db.prepare("PRAGMA user_version").get() as { user_version: number };
    if (schema.user_version !== 1) throw new Error("Unsupported signature database schema");
  } finally { db.close(); }
}

async function install() {
  try { await check(); console.log(`Signatures ${lock.version} already installed`); return; } catch { /* Fetch the pinned artifact. */ }
  const local = process.argv.indexOf("--file");
  let packed: Uint8Array;
  if (local >= 0) {
    if (!process.argv[local + 1]) throw new Error("--file requires a pinned release artifact");
    packed = await readFile(process.argv[local + 1]);
  } else {
    const url = `https://github.com/${lock.repository}/releases/download/${lock.version}/${lock.asset}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(120_000) });
    if (!response.ok) throw new Error(`Could not fetch signatures ${lock.version}: HTTP ${response.status}`);
    packed = new Uint8Array(await response.arrayBuffer());
  }
  if (hash(packed) !== lock.gzipSha256) throw new Error("Signature download checksum mismatch");
  const data = gunzipSync(packed, { maxOutputLength: 128 * 1024 * 1024 });
  if (hash(data) !== lock.sha256) throw new Error("Signature database checksum mismatch");
  await mkdir(join(root, "signatures"), { recursive: true });
  const temp = `${output}.${process.pid}.tmp`;
  try {
    await writeFile(temp, data);
    await check(temp);
    await rename(temp, output);
  } finally { await rm(temp, { force: true }); }
  console.log(`Signatures ${lock.version}: ${data.byteLength} bytes installed`);
}

if (import.meta.main) {
  if (process.argv.includes("--check")) await check();
  else await install();
}
