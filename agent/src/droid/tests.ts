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
import * as checksec from "./modules/checksec/index.js";
import * as activities from "./modules/activities.js";
import * as services from "./modules/services.js";
import * as receivers from "./modules/receivers.js";
import * as provider from "./modules/provider.js";
import * as device from "./modules/device.js";
import * as fs from "./modules/fs.js";
import * as apk from "./modules/apk.js";
import * as app from "./modules/app.js";
import * as classes from "./modules/classes.js";
import * as keystore from "./modules/keystore.js";
import * as lsof from "./modules/lsof.js";
import * as manifest from "./modules/manifest.js";
import * as rn from "./modules/rn.js";

async function testDevice() {
  console.log("\n--- device ---");

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
    console.log(
      `    model=${d.model} brand=${d.brand} sdk=${d.sdk} release=${d.release}`,
    );
  });

  await test("device.properties returns key-value map", async () => {
    const props = await device.properties();
    assertType(props, "object", "properties");
    const keys = Object.keys(props);
    assert(keys.length > 0, "properties should be non-empty");
    console.log(`    ${keys.length} properties`);
  });
}

async function testActivities() {
  console.log("\n--- activities ---");

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
    console.log(`    ${all.length} activities (${exported} exported)`);
    console.log(`    first: ${all[0].name}`);
  });

  await test("activities.start opens Android Settings", async () => {
    await activities.start({
      action: "android.settings.SETTINGS",
    });
    console.log("    started Settings activity");
  });
}

async function testServices() {
  console.log("\n--- services ---");

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
    console.log(`    ${all.length} services (${exported} exported)`);
    console.log(`    first: ${all[0].name}`);
  });

  skip(
    "services.start",
    "side-effect: requires a known safe service component",
  );
  skip("services.stop", "side-effect: requires a running service");
}

async function testReceivers() {
  console.log("\n--- receivers ---");

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
    console.log(`    ${all.length} receivers (${exported} exported)`);
    console.log(`    first: ${all[0].name}`);
  });

  await test("receivers.send with a no-op custom action", async () => {
    await receivers.send({
      action: "com.igf.test.NOOP_ACTION_" + Date.now(),
    });
    console.log("    broadcast sent (no receivers expected)");
  });
}

async function testProvider() {
  console.log("\n--- provider ---");

  await test("provider.list returns current app providers", async () => {
    const all = await provider.list();
    assertArray(all, "list");
    assertNonEmpty(all, "list");
    for (const p of all.slice(0, 3)) {
      assertKeys(
        p as unknown as Record<string, unknown>,
        ["name", "authority", "exported", "readPermission", "writePermission", "grantUriPermissions"],
        "provider entry",
      );
      assertType(p.name, "string", "name");
      assertType(p.exported, "boolean", "exported");
    }
    const exported = all.filter((p) => p.exported).length;
    console.log(`    ${all.length} providers (${exported} exported)`);
    console.log(`    first: ${all[0].name}`);
  });

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
    console.log(`    columns: ${result.columns.join(", ")}`);
    console.log(`    ${result.rows.length} rows`);
    if (result.rows.length > 0) {
      console.log(`    first row: ${json(result.rows[0])}`);
    }
  });

  await test("provider.query with no options returns full table", async () => {
    const result = await provider.query("content://settings/global");
    assertArray(result.columns, "columns");
    assertArray(result.rows, "rows");
    assertNonEmpty(result.rows, "rows");
    console.log(`    columns: ${result.columns.join(", ")}`);
    console.log(`    ${result.rows.length} rows (limited to 500)`);
  });

  await test("provider.query with sortOrder passes through param", async () => {
    const result = await provider.query("content://settings/global", {
      sortOrder: "name ASC",
    });
    assertNonEmpty(result.rows, "rows with sortOrder");
    console.log(`    ${result.rows.length} rows returned with sortOrder param`);
  });

  await test("provider.query with invalid uri handles gracefully", async () => {
    let threw = false;
    try {
      await provider.query("content://invalid.nonexistent.provider.12345/data");
    } catch (_) {
      threw = true;
    }
    if (!threw) console.log("    (returned empty result instead of throwing)");
    console.log("    handled gracefully");
  });

  skip("provider.insert", "side-effect: requires a writable content provider");
  skip("provider.update", "side-effect: requires a writable content provider");
  skip("provider.del", "side-effect: requires a writable content provider");
}

async function testFs() {
  console.log("\n--- fs ---");

  const { home, bundle } = await fs.roots();

  await test("fs.ls home returns app data directory listing", async () => {
    const result = await fs.ls(home);
    assertKeys(
      result as unknown as Record<string, unknown>,
      ["cwd", "writable", "list"],
      "ls result",
    );
    assertType(result.cwd, "string", "cwd");
    assertType(result.writable, "boolean", "writable");
    assertArray(result.list, "list");
    assert(result.cwd.startsWith("/"), "cwd should be absolute path");
    console.log(`    cwd=${result.cwd} writable=${result.writable}`);
    console.log(`    ${result.list.length} entries`);
    if (result.list.length > 0) {
      const first = result.list[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["name", "dir", "protection", "size", "alias", "created", "symlink"],
        "MetaData",
      );
      console.log(
        `    first: ${first.name} (dir=${first.dir} size=${first.size})`,
      );
    }
  });

  await test("fs.ls /proc returns entries", async () => {
    const result = await fs.ls("/proc");
    assertArray(result.list, "list");
    assertNonEmpty(result.list, "list");
    console.log(`    /proc has ${result.list.length} entries`);
  });

  await test("fs.ls with invalid path throws", async () => {
    let threw = false;
    try {
      await fs.ls("/nonexistent_path_12345");
    } catch (_) {
      threw = true;
    }
    assert(threw, "should throw for invalid path");
    console.log("    correctly threw for invalid path");
  });

  await test("fs.attrs on app data dir returns stat fields", async () => {
    const result = await fs.ls(home);
    const a = await fs.attrs(result.cwd);
    assertKeys(
      a as unknown as Record<string, unknown>,
      ["uid", "gid", "group", "owner", "perm", "protection", "size", "type", "created"],
      "attrs",
    );
    assertType(a.uid, "number", "uid");
    assertType(a.gid, "number", "gid");
    assertType(a.perm, "number", "perm");
    assertType(a.owner, "string", "owner");
    assertType(a.group, "string", "group");
    assertType(a.protection, "string", "protection");
    assert(a.type === "directory", `expected directory, got ${a.type}`);
    console.log(
      `    uid=${a.uid} gid=${a.gid} perm=${a.perm.toString(8)} type=${a.type}`,
    );
  });

  await test("fs.text reads a text file", async () => {
    const dir = home;
    const testPath = dir + "/igf_text_test_" + Date.now() + ".txt";
    await fs.saveText(testPath, "text read test content\n");

    const content = await fs.text(testPath);
    assertType(content, "string", "content");
    assert(content.length > 0, "content should be non-empty");
    assert(
      content === "text read test content\n",
      `content mismatch: ${json(content)}`,
    );
    console.log(`    read ${content.length} chars`);

    await fs.rm(testPath);
  });

  await test("fs.saveText + fs.text round-trip", async () => {
    const dir = home;
    const testPath = dir + "/igf_test_" + Date.now() + ".txt";
    const testContent = "hello from igf test\n";

    const ok = await fs.saveText(testPath, testContent);
    assert(ok === true, "saveText should return true");

    const readBack = await fs.text(testPath);
    assert(readBack === testContent, `round-trip mismatch: ${json(readBack)}`);
    console.log(`    wrote and read back ${testContent.length} chars`);

    // cleanup
    const deleted = await fs.rm(testPath);
    assert(deleted === true, "rm should return true");
    console.log("    cleaned up test file");
  });

  await test("fs.data reads binary data", async () => {
    const dir = home;
    const testPath = dir + "/igf_bin_test_" + Date.now() + ".bin";
    await fs.saveText(testPath, "binary test data");

    const buf = await fs.data(testPath);
    assert(buf !== null, "data should not return null");
    assert(buf!.byteLength > 0, "data should be non-empty");
    console.log(`    read ${buf!.byteLength} bytes`);

    await fs.rm(testPath);
  });

  await test("fs.preview reads limited data", async () => {
    const dir = home;
    const testPath = dir + "/igf_preview_test_" + Date.now() + ".txt";
    await fs.saveText(testPath, "preview test data content");

    const buf = await fs.preview(testPath);
    assert(buf !== null, "preview should not return null");
    assert(buf!.byteLength > 0, "preview should be non-empty");
    console.log(`    preview read ${buf!.byteLength} bytes`);

    await fs.rm(testPath);
  });

  await test("fs.cp copies a file", async () => {
    const dir = home;
    const srcPath = dir + "/igf_cp_src_" + Date.now() + ".txt";
    const dstPath = dir + "/igf_cp_dst_" + Date.now() + ".txt";

    await fs.saveText(srcPath, "copy test content\n");
    const ok = await fs.cp(srcPath, dstPath);
    assert(ok === true, "cp should return true");

    const content = await fs.text(dstPath);
    assert(content === "copy test content\n", `copy mismatch: ${json(content)}`);
    console.log("    copied and verified");

    await fs.rm(srcPath);
    await fs.rm(dstPath);
  });

  await test("fs.mv renames a file", async () => {
    const dir = home;
    const srcPath = dir + "/igf_mv_src_" + Date.now() + ".txt";
    const dstPath = dir + "/igf_mv_dst_" + Date.now() + ".txt";

    await fs.saveText(srcPath, "move test content\n");
    const ok = await fs.mv(srcPath, dstPath);
    assert(ok === true, "mv should return true");

    const content = await fs.text(dstPath);
    assert(content === "move test content\n", `move mismatch: ${json(content)}`);

    // src should no longer exist
    let srcExists = true;
    try {
      await fs.attrs(srcPath);
    } catch (_) {
      srcExists = false;
    }
    assert(!srcExists, "source should not exist after mv");
    console.log("    moved and verified");

    await fs.rm(dstPath);
  });

  await test("fs.mkdirp creates nested directories", async () => {
    const ts = Date.now();
    const topDir = home + "/igf_mkdirp_test_" + ts;
    const testDir = topDir + "/sub/dir";
    const ok = await fs.mkdirp(testDir);
    assert(ok === true, "mkdirp should return true");

    const result = await fs.ls(testDir);
    assertType(result.cwd, "string", "cwd");
    console.log(`    created ${testDir}`);

    await fs.rm(topDir);
    console.log("    cleaned up test directory");
  });

  await test("fs.access checks path writability", async () => {
    const writable = await fs.access(home);
    assertType(writable, "boolean", "access");
    console.log(`    home writable=${writable}`);
  });
}

async function testChecksec() {
  console.log("\n--- checksec ---");

  await test("checksec.all returns array of ELF results", async () => {
    const all = checksec.all();
    assertArray(all, "all");
    if (all.length === 0) {
      console.log("    (no native modules in /data/app, skipping assertions)");
      return;
    }
    const first = all[0];
    assertKeys(
      first as unknown as Record<string, unknown>,
      [
        "relro",
        "nx",
        "pie",
        "canary",
        "rpath",
        "runpath",
        "stripped",
        "fortify",
        "safeStack",
        "cfi",
      ],
      "checksec entry",
    );
    assertType(first.nx, "boolean", "nx");
    assertType(first.canary, "boolean", "canary");
    assertType(first.rpath, "boolean", "rpath");
    assertType(first.runpath, "boolean", "runpath");
    assertType(first.stripped, "boolean", "stripped");
    assertType(first.safeStack, "boolean", "safeStack");
    assertKeys(
      first.fortify as unknown as Record<string, unknown>,
      ["fortified", "fortifiable"],
      "fortify",
    );
    assertKeys(
      first.cfi as unknown as Record<string, unknown>,
      ["clang"],
      "cfi",
    );
    console.log(
      `    ${all.length} modules checked`,
    );
    console.log(
      `    first: relro=${first.relro} nx=${first.nx} pie=${first.pie} canary=${first.canary}`,
    );
  });

  await test("checksec.single returns result for named module", async () => {
    const [main] = Process.enumerateModules();
    const r = checksec.single(main.name);
    assert(r !== undefined, "should find main module by name");
    assertType(r!.nx, "boolean", "nx");
    console.log(`    checked ${main.name}: relro=${r!.relro} pie=${r!.pie}`);
  });

  await test("checksec.single returns undefined for unknown module", async () => {
    const r = checksec.single("__nonexistent_module_12345__");
    assert(r === undefined, "should return undefined for unknown module");
    console.log("    correctly returned undefined");
  });
}

async function testApp() {
  console.log("\n--- app ---");

  await test("app.info returns application metadata", async () => {
    const a = await app.info();
    assertKeys(
      a as unknown as Record<string, unknown>,
      [
        "packageName",
        "processName",
        "dataDir",
        "nativeLibraryDir",
        "publicSourceDir",
        "sourceDir",
        "uid",
        "minSdkVersion",
        "targetSdkVersion",
        "enabled",
        "flags",
      ],
      "app.info",
    );
    assertType(a.packageName, "string", "packageName");
    assertType(a.processName, "string", "processName");
    assertType(a.uid, "number", "uid");
    assertType(a.minSdkVersion, "number", "minSdkVersion");
    assertType(a.targetSdkVersion, "number", "targetSdkVersion");
    assertType(a.enabled, "boolean", "enabled");
    console.log(
      `    pkg=${a.packageName} uid=${a.uid} targetSdk=${a.targetSdkVersion}`,
    );
    console.log(`    dataDir=${a.dataDir}`);
  });
}

async function testManifest() {
  console.log("\n--- manifest ---");

  await test("manifest.xml returns AndroidManifest XML", async () => {
    const xml = await manifest.xml();
    assertType(xml, "string", "xml");
    assert(xml.length > 0, "xml should be non-empty");
    assert(
      xml.includes("<manifest"),
      "xml should contain <manifest element",
    );
    console.log(`    ${xml.length} chars`);
  });
}

async function testApk() {
  console.log("\n--- apk ---");

  skip("apk.list", "requires file-system access to APK on device");
  skip("apk.ls", "requires file-system access to APK on device");
  skip("apk.size", "requires file-system access to APK on device");
  skip("apk.read", "requires file-system access to APK on device");
}

async function testClasses() {
  console.log("\n--- classes ---");

  await test("classes.list returns loaded Java classes", async () => {
    const all = await classes.list();
    assertArray(all, "list");
    assertNonEmpty(all, "list");
    for (const c of all.slice(0, 3)) {
      assertType(c, "string", "class name");
    }
    console.log(`    ${all.length} loaded classes`);
    console.log(`    first: ${all[0]}`);
  });

  await test("classes.inspect returns class detail", async () => {
    const detail = await classes.inspect("java.lang.Object");
    assertKeys(
      detail as unknown as Record<string, unknown>,
      ["name", "superClass", "interfaces", "methods", "ownMethods", "fields"],
      "inspect",
    );
    assert(detail.name === "java.lang.Object", `name mismatch: ${detail.name}`);
    assertArray(detail.methods, "methods");
    assertNonEmpty(detail.methods, "methods");
    assertArray(detail.interfaces, "interfaces");
    assertArray(detail.fields, "fields");
    console.log(
      `    name=${detail.name} methods=${detail.methods.length} fields=${detail.fields.length}`,
    );
  });

  await test("classes.inspect method entries have expected keys", async () => {
    const detail = await classes.inspect("java.lang.Object");
    const m = detail.methods[0];
    assertKeys(
      m as unknown as Record<string, unknown>,
      ["name", "returnType", "argumentTypes", "isStatic"],
      "method entry",
    );
    assertType(m.name, "string", "method name");
    assertType(m.returnType, "string", "returnType");
    assertArray(m.argumentTypes, "argumentTypes");
    assertType(m.isStatic, "boolean", "isStatic");
    console.log(`    sample method: ${m.name}`);
  });

  await test("classes.inspect on nonexistent class throws", async () => {
    let threw = false;
    try {
      await classes.inspect("__IGFNonExistentClass12345__");
    } catch (_) {
      threw = true;
    }
    assert(threw, "should throw for nonexistent class");
    console.log("    correctly threw for nonexistent class");
  });
}

async function testKeystore() {
  console.log("\n--- keystore ---");

  await test("keystore.aliases returns array of aliases", async () => {
    const all = await keystore.aliases();
    assertArray(all, "aliases");
    console.log(`    ${all.length} keystore aliases`);
    if (all.length > 0) {
      const first = all[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["alias", "algorithm", "entryType"],
        "keystore alias",
      );
      assertType(first.alias, "string", "alias");
      assertType(first.entryType, "string", "entryType");
      console.log(
        `    first: alias=${first.alias} type=${first.entryType} algo=${first.algorithm}`,
      );
    }
  });

  await test("keystore.info returns key details for known alias", async () => {
    const all = await keystore.aliases();
    if (all.length === 0) {
      console.log("    (no aliases to inspect, skipping)");
      return;
    }
    const k = await keystore.info(all[0].alias);
    if (k === null) {
      console.log("    (info returned null for first alias)");
      return;
    }
    assertKeys(
      k as unknown as Record<string, unknown>,
      ["alias", "algorithm", "keySize", "blockModes", "digests", "purposes"],
      "keyInfo",
    );
    assertType(k.alias, "string", "alias");
    assertType(k.algorithm, "string", "algorithm");
    assertType(k.keySize, "number", "keySize");
    console.log(`    alias=${k.alias} algo=${k.algorithm} size=${k.keySize}`);
  });

  await test("keystore.info returns null for unknown alias", async () => {
    const k = await keystore.info("__nonexistent_alias_12345__");
    assert(k === null, "should return null for unknown alias");
    console.log("    correctly returned null");
  });
}

async function testLsof() {
  console.log("\n--- lsof ---");

  await test("lsof.fds returns open file descriptors", async () => {
    const all = lsof.fds();
    assertArray(all, "fds");
    assertNonEmpty(all, "fds");

    const files = all.filter((fd) => fd.type === "file");
    const tcp = all.filter((fd) => fd.type === "tcp" || fd.type === "tcp6");
    const udp = all.filter((fd) => fd.type === "udp" || fd.type === "udp6");
    console.log(
      `    ${all.length} open fds (${files.length} files, ${tcp.length} tcp, ${udp.length} udp)`,
    );

    if (files.length > 0) {
      const f = files[0] as { fd: number; path: string };
      assertType(f.fd, "number", "fd");
      assertType(f.path, "string", "path");
      console.log(`    first file: fd=${f.fd} path=${f.path}`);
    }
  });
}

async function testRn() {
  console.log("\n--- rn ---");

  await test("rn.arch returns architecture flags", async () => {
    const a = await rn.arch();
    assertKeys(
      a as unknown as Record<string, unknown>,
      ["legacy", "bridgeless"],
      "rn.arch",
    );
    assertType(a.legacy, "boolean", "legacy");
    assertType(a.bridgeless, "boolean", "bridgeless");
    console.log(`    legacy=${a.legacy} bridgeless=${a.bridgeless}`);
  });

  await test("rn.list returns RN instances array", async () => {
    const instances = await rn.list();
    assertArray(instances, "list");
    console.log(`    ${instances.length} React Native instances`);
    if (instances.length > 0) {
      const first = instances[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["className", "arch", "handle"],
        "RNInstance",
      );
      assertType(first.handle, "string", "handle");
      console.log(`    first: class=${first.className} arch=${first.arch}`);
    }
  });

  skip("rn.inject", "side-effect: injects script into React Native");
}

async function run() {
  console.log("=== droid module tests ===");

  await testDevice();
  await testApp();
  await testManifest();
  await testChecksec();
  await testActivities();
  await testServices();
  await testReceivers();
  await testProvider();
  await testApk();
  await testClasses();
  await testKeystore();
  await testLsof();
  await testFs();
  await testRn();

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
          console.log(
            `\nFATAL: ${e instanceof Error ? e.stack || e.message : String(e)}`,
          );
        });
      },
    },
  });

  const handler = Handler.$new(Looper.getMainLooper());
  handler.post(RunnableImpl.$new());
});
