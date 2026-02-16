/**
 * Droid module test suite — current app only.
 *
 * Usage:
 *   frida-compile src/droid/tests.ts -o /tmp/tests.js
 *   frida -U <app> -l /tmp/tests.js
 *
 *   or directly:
 *   frida -U <app> -l src/droid/tests.ts
 */

import Java from "frida-java-bridge";

import {
  test,
  skip,
  json,
  assert,
  assertType,
  assertArray,
  assertKeys,
  assertNonEmpty,
  summary,
} from "@/common/test-runner.js";
import * as activities from "./modules/activities.js";
import * as services from "./modules/services.js";
import * as receivers from "./modules/receivers.js";
import * as provider from "./modules/provider.js";
import * as device from "./modules/device.js";
import * as fs from "./modules/fs.js";

// ---------------------------------------------------------------------------
// test suites
// ---------------------------------------------------------------------------

async function testDevice() {
  log("\n--- device ---");

  await test("device.info returns build fields", async () => {
    const d = await device.info();
    assertKeys(
      d as unknown as Record<string, unknown>,
      ["model", "brand", "manufacturer", "sdk", "release", "fingerprint"],
      "device.info",
    );
    assertType(d.sdk, "number", "sdk");
    assert(d.sdk > 0, "sdk should be > 0");
    assertType(d.model, "string", "model");
    assert(d.model.length > 0, "model should be non-empty");
    log(
      `    model=${d.model} brand=${d.brand} sdk=${d.sdk} release=${d.release}`,
    );
  });

  await test("device.properties returns key-value map", async () => {
    const props = await device.properties();
    assertType(props, "object", "properties");
    const keys = Object.keys(props);
    assert(keys.length > 0, "properties should be non-empty");
    log(`    ${keys.length} properties`);
  });
}

async function testActivities() {
  log("\n--- activities ---");

  await test("activities.list returns current app activities", async () => {
    const all = await activities.list();
    assertArray(all, "list");
    assertNonEmpty(all, "list");
    for (const a of all.slice(0, 3)) {
      assertKeys(
        a as unknown as Record<string, unknown>,
        ["name", "exported", "permission"],
        "activity entry",
      );
      assertType(a.name, "string", "name");
      assertType(a.exported, "boolean", "exported");
    }
    const exported = all.filter((a) => a.exported).length;
    log(`    ${all.length} activities (${exported} exported)`);
    log(`    first: ${all[0].name}`);
  });

  await test("activities.start opens Android Settings", async () => {
    await activities.start({
      action: "android.settings.SETTINGS",
    });
    log("    started Settings activity");
  });
}

async function testServices() {
  log("\n--- services ---");

  await test("services.list returns current app services", async () => {
    const all = await services.list();
    assertArray(all, "list");
    assertNonEmpty(all, "list");
    for (const s of all.slice(0, 3)) {
      assertKeys(
        s as unknown as Record<string, unknown>,
        ["name", "exported", "permission"],
        "service entry",
      );
    }
    const exported = all.filter((s) => s.exported).length;
    log(`    ${all.length} services (${exported} exported)`);
    log(`    first: ${all[0].name}`);
  });

  skip(
    "services.start",
    "side-effect: requires a known safe service component",
  );
  skip("services.stop", "side-effect: requires a running service");
}

async function testReceivers() {
  log("\n--- receivers ---");

  await test("receivers.list returns current app receivers", async () => {
    const all = await receivers.list();
    assertArray(all, "list");
    assertNonEmpty(all, "list");
    for (const r of all.slice(0, 3)) {
      assertKeys(
        r as unknown as Record<string, unknown>,
        ["name", "exported", "permission"],
        "receiver entry",
      );
    }
    const exported = all.filter((r) => r.exported).length;
    log(`    ${all.length} receivers (${exported} exported)`);
    log(`    first: ${all[0].name}`);
  });

  await test("receivers.send with a no-op custom action", async () => {
    await receivers.send({
      action: "com.igf.test.NOOP_ACTION_" + Date.now(),
    });
    log("    broadcast sent (no receivers expected)");
  });
}

async function testProvider() {
  log("\n--- provider ---");

  await test("provider.query settings/secure with selection", async () => {
    const result = await provider.query("content://settings/secure", {
      projection: ["name", "value"],
      selection: "name=?",
      selectionArgs: ["android_id"],
    });
    assertKeys(
      result as unknown as Record<string, unknown>,
      ["columns", "rows"],
      "query result",
    );
    assertArray(result.columns, "columns");
    assertArray(result.rows, "rows");
    assert(
      result.columns.length === 2,
      `expected 2 columns, got ${result.columns.length}`,
    );
    log(`    columns: ${result.columns.join(", ")}`);
    log(`    ${result.rows.length} rows`);
    if (result.rows.length > 0) {
      log(`    first row: ${json(result.rows[0])}`);
    }
  });

  await test("provider.query with no options returns full table", async () => {
    const result = await provider.query("content://settings/global");
    assertArray(result.columns, "columns");
    assertArray(result.rows, "rows");
    assertNonEmpty(result.rows, "rows");
    log(`    columns: ${result.columns.join(", ")}`);
    log(`    ${result.rows.length} rows (limited to 500)`);
  });

  await test("provider.query with sortOrder passes through param", async () => {
    const result = await provider.query("content://settings/global", {
      sortOrder: "name ASC",
    });
    assertNonEmpty(result.rows, "rows with sortOrder");
    log(`    ${result.rows.length} rows returned with sortOrder param`);
  });

  await test("provider.query with invalid uri handles gracefully", async () => {
    let threw = false;
    try {
      await provider.query("content://invalid.nonexistent.provider.12345/data");
    } catch (_) {
      threw = true;
    }
    if (!threw) log("    (returned empty result instead of throwing)");
    log("    handled gracefully");
  });

  skip("provider.insert", "side-effect: requires a writable content provider");
  skip("provider.update", "side-effect: requires a writable content provider");
  skip("provider.del", "side-effect: requires a writable content provider");
}

async function testFs() {
  log("\n--- fs ---");

  await test("fs.ls ~ returns app data directory listing", async () => {
    const result = await fs.ls("~");
    assertKeys(
      result as unknown as Record<string, unknown>,
      ["cwd", "list"],
      "ls result",
    );
    assertType(result.cwd, "string", "cwd");
    assertArray(result.list, "list");
    assert(result.cwd.startsWith("/"), "cwd should be absolute path");
    log(`    cwd=${result.cwd}`);
    log(`    ${result.list.length} entries`);
    if (result.list.length > 0) {
      const first = result.list[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["name", "dir", "size", "created", "symlink", "writable"],
        "MetaData",
      );
      log(`    first: ${first.name} (dir=${first.dir} size=${first.size})`);
    }
  });

  await test("fs.ls /proc returns entries", async () => {
    const result = await fs.ls("/proc");
    assertArray(result.list, "list");
    assertNonEmpty(result.list, "list");
    log(`    /proc has ${result.list.length} entries`);
  });

  await test("fs.ls with invalid path throws", async () => {
    let threw = false;
    try {
      await fs.ls("/nonexistent_path_12345");
    } catch (_) {
      threw = true;
    }
    assert(threw, "should throw for invalid path");
    log("    correctly threw for invalid path");
  });

  await test("fs.attrs on app data dir returns stat fields", async () => {
    const result = await fs.ls("~");
    const a = await fs.attrs(result.cwd);
    assertKeys(
      a as unknown as Record<string, unknown>,
      ["uid", "gid", "perm", "size", "type", "created"],
      "attrs",
    );
    assertType(a.uid, "number", "uid");
    assertType(a.gid, "number", "gid");
    assertType(a.perm, "number", "perm");
    assert(a.type === "directory", `expected directory, got ${a.type}`);
    log(
      `    uid=${a.uid} gid=${a.gid} perm=${a.perm.toString(8)} type=${a.type}`,
    );
  });

  await test("fs.text reads a text file", async () => {
    const dir = (await fs.ls("~")).cwd;
    const testPath = dir + "/igf_text_test_" + Date.now() + ".txt";
    await fs.saveText(testPath, "text read test content\n");

    const content = await fs.text(testPath);
    assertType(content, "string", "content");
    assert(content.length > 0, "content should be non-empty");
    assert(
      content === "text read test content\n",
      `content mismatch: ${json(content)}`,
    );
    log(`    read ${content.length} chars`);

    await fs.rm(testPath);
  });

  await test("fs.saveText + fs.text round-trip", async () => {
    const dir = (await fs.ls("~")).cwd;
    const testPath = dir + "/igf_test_" + Date.now() + ".txt";
    const testContent = "hello from igf test\n";

    const ok = await fs.saveText(testPath, testContent);
    assert(ok === true, "saveText should return true");

    const readBack = await fs.text(testPath);
    assert(readBack === testContent, `round-trip mismatch: ${json(readBack)}`);
    log(`    wrote and read back ${testContent.length} chars`);

    // cleanup
    const deleted = await fs.rm(testPath);
    assert(deleted === true, "rm should return true");
    log("    cleaned up test file");
  });

  await test("fs.data reads binary data", async () => {
    const dir = (await fs.ls("~")).cwd;
    const testPath = dir + "/igf_bin_test_" + Date.now() + ".bin";
    await fs.saveText(testPath, "binary test data");

    const buf = await fs.data(testPath);
    assert(buf !== null, "data should not return null");
    assert(buf!.byteLength > 0, "data should be non-empty");
    log(`    read ${buf!.byteLength} bytes`);

    await fs.rm(testPath);
  });

  await test("fs.preview reads limited data", async () => {
    const dir = (await fs.ls("~")).cwd;
    const testPath = dir + "/igf_preview_test_" + Date.now() + ".txt";
    await fs.saveText(testPath, "preview test data content");

    const buf = await fs.preview(testPath);
    assert(buf !== null, "preview should not return null");
    assert(buf!.byteLength > 0, "preview should be non-empty");
    log(`    preview read ${buf!.byteLength} bytes`);

    await fs.rm(testPath);
  });

  await test("fs.cp copies a file", async () => {
    const dir = (await fs.ls("~")).cwd;
    const srcPath = dir + "/igf_cp_src_" + Date.now() + ".txt";
    const dstPath = dir + "/igf_cp_dst_" + Date.now() + ".txt";

    await fs.saveText(srcPath, "copy test content");
    const ok = await fs.cp(srcPath, dstPath);
    assert(ok === true, "cp should return true");

    const content = await fs.text(dstPath);
    assert(content === "copy test content", `copy mismatch: ${json(content)}`);
    log("    copied and verified");

    await fs.rm(srcPath);
    await fs.rm(dstPath);
  });

  await test("fs.mv renames a file", async () => {
    const dir = (await fs.ls("~")).cwd;
    const srcPath = dir + "/igf_mv_src_" + Date.now() + ".txt";
    const dstPath = dir + "/igf_mv_dst_" + Date.now() + ".txt";

    await fs.saveText(srcPath, "move test content");
    const ok = await fs.mv(srcPath, dstPath);
    assert(ok === true, "mv should return true");

    const content = await fs.text(dstPath);
    assert(content === "move test content", `move mismatch: ${json(content)}`);

    // src should no longer exist
    let srcExists = true;
    try {
      await fs.attrs(srcPath);
    } catch (_) {
      srcExists = false;
    }
    assert(!srcExists, "source should not exist after mv");
    log("    moved and verified");

    await fs.rm(dstPath);
  });

  await test("fs.expandPath ~ resolves to app data dir", async () => {
    const result = await fs.ls("~");
    assert(
      result.cwd.includes("/data/"),
      `expected data path, got ${result.cwd}`,
    );
    log(`    ~ = ${result.cwd}`);
  });
}

// ---------------------------------------------------------------------------
// runner
// ---------------------------------------------------------------------------

async function run() {
  log("=== droid module tests ===");

  await testDevice();
  await testActivities();
  await testServices();
  await testReceivers();
  await testProvider();
  await testFs();

  summary();
}

Java.perform(() => {
  const Handler = Java.use("android.os.Handler");
  const Looper = Java.use("android.os.Looper");
  const Runnable = Java.use("java.lang.Runnable");

  const RunnableImpl = Java.registerClass({
    name: "com.igf.test.TestRunner",
    implements: [Runnable],
    methods: {
      run() {
        run().catch((e) => {
          log(
            `\nFATAL: ${e instanceof Error ? e.stack || e.message : String(e)}`,
          );
        });
      },
    },
  });

  const handler = Handler.$new(Looper.getMainLooper());
  handler.post(RunnableImpl.$new());
});
