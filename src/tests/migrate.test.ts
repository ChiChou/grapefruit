import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { it } from "node:test";

it("migrates a fresh project once across simultaneous server processes", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "igf-migrate-"));
  const url = new URL("../lib/store/db.ts", import.meta.url).href;
  const children = Array.from({ length: 4 }, () => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", `
      console.log("ready");
      await new Promise(resolve => process.stdin.once("data", resolve));
      const { db } = await import(${JSON.stringify(url)});
      db.$client.close();
      process.stdin.destroy();
    `], { env: { ...process.env, PROJECT_DIR: dir } });
    let stderr = "";
    child.stderr.on("data", (data) => { stderr += data; });
    const ready = new Promise<void>((resolve, reject) => {
      child.stdout.once("data", () => resolve());
      child.once("error", reject);
    });
    const done = new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code) => {
        if (code === 0) resolve();
        else reject(new Error(`Migration process exited ${code}: ${stderr}`));
      });
    });
    return { child, ready, done };
  });
  try {
    await Promise.all(children.map(({ ready }) => ready));
    for (const { child } of children) child.stdin.end("go");
    await Promise.all(children.map(({ done }) => done));
    const client = new DatabaseSync(path.join(dir, "data/data.db"));
    try {
      const rows = client.prepare("SELECT hash FROM __drizzle_migrations").all();
      assert(rows.length > 0);
      assert.equal(new Set(rows.map((row) => row.hash)).size, rows.length);
    } finally {
      client.close();
    }
  } finally {
    for (const { child } of children) child.kill();
    await Promise.allSettled(children.map(({ done }) => done));
    await rm(dir, { recursive: true, force: true });
  }
});
