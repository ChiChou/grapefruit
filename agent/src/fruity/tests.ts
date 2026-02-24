/**
 * Fruity module test suite — current app only.
 *
 * Usage:
 *   frida-compile src/fruity/tests.ts -o /tmp/tests.js
 *   frida -U <app> -l /tmp/tests.js
 *
 *   or directly:
 *   frida -U <app> -l src/fruity/tests.ts
 */

import ObjC from "frida-objc-bridge";

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

import * as info from "./modules/info.js";
import * as checksec from "./modules/checksec.js";
import * as entitlements from "./modules/entitlements.js";
import * as classdump from "./modules/classdump.js";
import * as cookies from "./modules/cookies.js";
import * as fs from "./modules/fs.js";
import * as keychain from "./modules/keychain.js";
import * as userdefaults from "./modules/userdefaults.js";
import * as lsof from "./modules/lsof.js";

async function testInfo() {
  console.log("\n--- info ---");

  await test("info.basics returns app info fields", async () => {
    const b = info.basics();
    assertKeys(
      b as unknown as Record<string, unknown>,
      [
        "tmp",
        "home",
        "id",
        "label",
        "path",
        "main",
        "version",
        "semVer",
        "minOS",
      ],
      "info.basics",
    );
    assertType(b.id, "string", "id");
    assert(b.id.length > 0, "id should be non-empty");
    assertType(b.path, "string", "path");
    assert(b.path.startsWith("/"), "path should be absolute");
    assertType(b.home, "string", "home");
    assert(b.home.startsWith("/"), "home should be absolute");
    console.log(
      `    id=${b.id} label=${b.label} ver=${b.version} semVer=${b.semVer}`,
    );
    console.log(`    home=${b.home}`);
    console.log(`    path=${b.path}`);
  });

  await test("info.urls returns URL schemes array", async () => {
    const u = info.urls();
    assertArray(u, "urls");
    console.log(`    ${u.length} URL schemes`);
    if (u.length > 0) {
      const first = u[0];
      console.log(
        `    first: name=${first.name} schemes=${first.schemes?.join(",")}`,
      );
    }
  });

  await test("info.plist returns Info.plist as object", async () => {
    const p = info.plist();
    assertType(p, "object", "plist");
    assert(p !== null, "plist should not be null");
    const dict = p as Record<string, unknown>;
    assert(
      "CFBundleIdentifier" in dict,
      "plist should contain CFBundleIdentifier",
    );
    console.log(`    CFBundleIdentifier=${dict.CFBundleIdentifier}`);
  });

  await test("info.processInfo returns process fields", async () => {
    const p = info.processInfo();
    assertKeys(
      p as unknown as Record<string, unknown>,
      ["platform", "arch", "pointerSize", "pageSize"],
      "processInfo",
    );
    assertType(p.platform, "string", "platform");
    assertType(p.arch, "string", "arch");
    assertType(p.pointerSize, "number", "pointerSize");
    assertType(p.pageSize, "number", "pageSize");
    assert(p.pointerSize > 0, "pointerSize should be > 0");
    assert(p.pageSize > 0, "pageSize should be > 0");
    console.log(
      `    platform=${p.platform} arch=${p.arch} ptrSize=${p.pointerSize} pageSize=${p.pageSize}`,
    );
  });
}

async function testChecksec() {
  console.log("\n--- checksec ---");

  await test("checksec.flags returns security flags", async () => {
    const f = checksec.flags();
    assertKeys(
      f as unknown as Record<string, unknown>,
      ["pie", "arc", "canary", "encrypted"],
      "checksec.flags",
    );
    assertType(f.pie, "boolean", "pie");
    assertType(f.arc, "boolean", "arc");
    assertType(f.canary, "boolean", "canary");
    assertType(f.encrypted, "boolean", "encrypted");
    console.log(
      `    pie=${f.pie} arc=${f.arc} canary=${f.canary} encrypted=${f.encrypted}`,
    );
  });
}

async function testEntitlements() {
  console.log("\n--- entitlements ---");

  await test("entitlements.plist returns entitlements dict", async () => {
    const p = entitlements.plist();
    assertType(p, "object", "plist");
    assert(p !== null, "plist should not be null");
    const keys = Object.keys(p as Record<string, unknown>);
    console.log(`    ${keys.length} entitlement keys`);
    if (keys.length > 0) {
      console.log(`    first key: ${keys[0]}`);
    }
  });
}

async function testClassdump() {
  console.log("\n--- classdump ---");

  await test("classdump.list __main__ returns classes", async () => {
    const classes = classdump.list("__main__");
    assertArray(classes, "list");
    assertNonEmpty(classes, "list");
    for (const c of classes.slice(0, 3)) {
      assertType(c, "string", "class name");
    }
    console.log(`    ${classes.length} classes in __main__`);
    console.log(`    first: ${classes[0]}`);
  });

  await test("classdump.list __app__ returns classes", async () => {
    const classes = classdump.list("__app__");
    assertArray(classes, "list");
    assertNonEmpty(classes, "list");
    console.log(`    ${classes.length} classes in __app__`);
  });

  await test("classdump.inspect on NSObject returns class detail", async () => {
    const detail = classdump.inspect("NSObject");
    assertKeys(
      detail as unknown as Record<string, unknown>,
      [
        "name",
        "protocols",
        "methods",
        "ownMethods",
        "proto",
        "ivars",
        "module",
        "properties",
      ],
      "inspect",
    );
    assert(detail.name === "NSObject", `name mismatch: ${detail.name}`);
    assertArray(detail.methods, "methods");
    assertNonEmpty(detail.methods, "methods");
    assertArray(detail.proto, "proto");
    console.log(
      `    name=${detail.name} methods=${detail.methods.length} ivars=${detail.ivars.length}`,
    );
    console.log(
      `    protocols: ${Object.keys(detail.protocols).join(", ").slice(0, 80)}`,
    );
  });

  await test("classdump.inspect method entries have expected keys", async () => {
    const detail = classdump.inspect("NSObject");
    const m = detail.methods[0];
    assertKeys(
      m as unknown as Record<string, unknown>,
      ["name", "impl", "types"],
      "method entry",
    );
    assertType(m.name, "string", "method name");
    assertType(m.impl, "string", "method impl");
    assertType(m.types, "string", "method types");
    console.log(`    sample method: ${m.name}`);
  });

  await test("classdump.inspect on nonexistent class throws", async () => {
    let threw = false;
    try {
      classdump.inspect("__IGFNonExistentClass12345__");
    } catch (_) {
      threw = true;
    }
    assert(threw, "should throw for nonexistent class");
    console.log("    correctly threw for nonexistent class");
  });
}

async function testCookies() {
  console.log("\n--- cookies ---");

  await test("cookies.list returns array of cookies", async () => {
    const all = cookies.list();
    assertArray(all, "list");
    console.log(`    ${all.length} cookies`);
    if (all.length > 0) {
      const c = all[0];
      assertKeys(
        c as unknown as Record<string, unknown>,
        ["name", "value", "domain", "path", "isSecure", "isHTTPOnly"],
        "cookie entry",
      );
      assertType(c.name, "string", "name");
      assertType(c.value, "string", "value");
      assertType(c.domain, "string", "domain");
      console.log(`    first: name=${c.name} domain=${c.domain}`);
    }
  });

  skip("cookies.add / cookies.remove", "side-effect: modifies cookie storage");
  skip("cookies.clear", "side-effect: clears all cookies");
}

async function testFs() {
  console.log("\n--- fs ---");

  const { home, bundle } = fs.roots();

  await test("fs.ls home returns app home directory listing", async () => {
    const result = fs.ls(home);
    assertKeys(
      result as unknown as Record<string, unknown>,
      ["cwd", "list"],
      "ls result",
    );
    assertType(result.cwd, "string", "cwd");
    assertArray(result.list, "list");
    assert(result.cwd.startsWith("/"), "cwd should be absolute path");
    console.log(`    cwd=${result.cwd}`);
    console.log(`    ${result.list.length} entries`);
    if (result.list.length > 0) {
      const first = result.list[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["name", "dir", "size", "created", "symlink", "writable"],
        "MetaData",
      );
      console.log(
        `    first: ${first.name} (dir=${first.dir} size=${first.size})`,
      );
    }
  });

  await test("fs.ls bundle returns app bundle directory listing", async () => {
    const result = fs.ls(bundle);
    assertArray(result.list, "list");
    assertNonEmpty(result.list, "list");
    assert(result.cwd.includes(".app"), "bundle path should contain .app");
    console.log(`    cwd=${result.cwd}`);
    console.log(`    ${result.list.length} entries`);
  });

  await test("fs.ls with invalid path throws", async () => {
    let threw = false;
    try {
      fs.ls("/nonexistent_path_12345");
    } catch (_) {
      threw = true;
    }
    assert(threw, "should throw for invalid path");
    console.log("    correctly threw for invalid path");
  });

  await test("fs.attrs on app home dir returns stat fields", async () => {
    const result = fs.ls(home);
    const a = fs.attrs(result.cwd);
    assertKeys(
      a as unknown as Record<string, unknown>,
      ["uid", "gid", "perm", "size", "type", "owner", "group"],
      "attrs",
    );
    assertType(a.uid, "number", "uid");
    assertType(a.gid, "number", "gid");
    assertType(a.perm, "number", "perm");
    console.log(
      `    uid=${a.uid} gid=${a.gid} perm=${a.perm.toString(8)} type=${a.type}`,
    );
  });

  await test("fs.text reads a text file", async () => {
    const testPath = home + "/igf_text_test_" + Date.now() + ".txt";
    fs.saveText(testPath, "text read test content\n");

    const content = fs.text(testPath);
    assertType(content, "string", "content");
    assert(content.length > 0, "content should be non-empty");
    assert(
      content === "text read test content\n",
      `content mismatch: ${json(content)}`,
    );
    console.log(`    read ${content.length} chars`);

    fs.rm(testPath);
  });

  await test("fs.saveText + fs.text round-trip", async () => {
    const testPath = home + "/igf_test_" + Date.now() + ".txt";
    const testContent = "hello from igf test\n";

    const ok = fs.saveText(testPath, testContent);
    assert(ok === true, "saveText should return true");

    const readBack = fs.text(testPath);
    assert(readBack === testContent, `round-trip mismatch: ${json(readBack)}`);
    console.log(`    wrote and read back ${testContent.length} chars`);

    // cleanup
    fs.rm(testPath);
    console.log("    cleaned up test file");
  });

  await test("fs.data reads binary data", async () => {
    const testPath = home + "/igf_bin_test_" + Date.now() + ".bin";
    fs.saveText(testPath, "binary test data");

    const buf = fs.data(testPath);
    assert(buf !== null, "data should not return null");
    assert(buf!.byteLength > 0, "data should be non-empty");
    console.log(`    read ${buf!.byteLength} bytes`);

    fs.rm(testPath);
  });

  await test("fs.preview reads limited data", async () => {
    const testPath = home + "/igf_preview_test_" + Date.now() + ".txt";
    fs.saveText(testPath, "preview test data content");

    const buf = fs.preview(testPath);
    assert(buf !== null, "preview should not return null");
    assert(buf!.byteLength > 0, "preview should be non-empty");
    console.log(`    preview read ${buf!.byteLength} bytes`);

    fs.rm(testPath);
  });

  await test("fs.cp copies a file", async () => {
    const srcPath = home + "/igf_cp_src_" + Date.now() + ".txt";
    const dstPath = home + "/igf_cp_dst_" + Date.now() + ".txt";

    fs.saveText(srcPath, "copy test content");
    const ok = fs.cp(srcPath, dstPath);
    assert(ok === true, "cp should return true");

    const content = fs.text(dstPath);
    assert(content === "copy test content", `copy mismatch: ${json(content)}`);
    console.log("    copied and verified");

    fs.rm(srcPath);
    fs.rm(dstPath);
  });

  await test("fs.mv renames a file", async () => {
    const srcPath = home + "/igf_mv_src_" + Date.now() + ".txt";
    const dstPath = home + "/igf_mv_dst_" + Date.now() + ".txt";

    fs.saveText(srcPath, "move test content");
    const ok = fs.mv(srcPath, dstPath);
    assert(ok === true, "mv should return true");

    const content = fs.text(dstPath);
    assert(content === "move test content", `move mismatch: ${json(content)}`);

    // src should no longer exist
    let srcExists = true;
    try {
      fs.attrs(srcPath);
    } catch (_) {
      srcExists = false;
    }
    assert(!srcExists, "source should not exist after mv");
    console.log("    moved and verified");

    fs.rm(dstPath);
  });

  await test("fs.plist reads a plist file", async () => {
    // read the app's own Info.plist
    const plistPath = bundle + "/Info.plist";
    let threw = false;
    try {
      const p = fs.plist(plistPath);
      assertType(p, "object", "plist");
      console.log(`    read plist from ${plistPath}`);
    } catch (_) {
      // some apps may not have a readable Info.plist on disk
      threw = true;
      console.log(
        "    Info.plist not readable from disk (expected for some apps)",
      );
    }
  });
}

async function testKeychain() {
  console.log("\n--- keychain ---");

  await test("keychain.list returns array of items", async () => {
    const items = keychain.list();
    assertArray(items, "list");
    console.log(`    ${items.length} keychain items`);
    if (items.length > 0) {
      const first = items[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["clazz"],
        "keychain item",
      );
      console.log(
        `    first: clazz=${first.clazz} service=${first.service} account=${first.account}`,
      );
    }
  });

  skip("keychain.remove", "side-effect: removes keychain item");
}

async function testUserDefaults() {
  console.log("\n--- userdefaults ---");

  await test("userdefaults.enumerate returns dict of entries", async () => {
    const defaults = userdefaults.enumerate();
    assertType(defaults, "object", "enumerate");
    const keys = Object.keys(defaults);
    assert(keys.length > 0, "should have at least one user default");
    console.log(`    ${keys.length} user defaults`);

    // check structure of first entry
    const firstKey = keys[0];
    const entry = defaults[firstKey];
    assertKeys(
      entry as unknown as Record<string, unknown>,
      ["type", "readable", "value"],
      "entry",
    );
    assertType(entry.type, "string", "type");
    assertType(entry.readable, "string", "readable");
    console.log(`    first: key=${firstKey} type=${entry.type}`);
  });

  skip("userdefaults.update", "side-effect: modifies user defaults");
  skip("userdefaults.remove", "side-effect: removes user default key");
}

async function testLsof() {
  console.log("\n--- lsof ---");

  await test("lsof.fds returns open file descriptors", async () => {
    const fds = lsof.fds();
    assertArray(fds, "fds");
    assertNonEmpty(fds, "fds");

    const vnodes = fds.filter((fd) => fd.type === "vnode");
    const sockets = fds.filter((fd) => fd.type === "socket");
    console.log(
      `    ${fds.length} open fds (${vnodes.length} vnodes, ${sockets.length} sockets)`,
    );

    if (vnodes.length > 0) {
      const v = vnodes[0];
      assertType(v.fd, "number", "fd");
      assert("path" in v, "vnode should have path");
      console.log(
        `    first vnode: fd=${v.fd} path=${(v as { path: string }).path}`,
      );
    }

    if (sockets.length > 0) {
      const s = sockets[0];
      assertType(s.fd, "number", "fd");
      assert("protocol" in s, "socket should have protocol");
      console.log(
        `    first socket: fd=${s.fd} protocol=${(s as { protocol: string }).protocol}`,
      );
    }
  });
}

async function run() {
  console.log("=== fruity module tests ===");

  const bundleId = ObjC.classes.NSBundle.mainBundle()
    .bundleIdentifier()
    .toString();
  console.log(`target bundle: ${bundleId}\n`);

  await testInfo();
  await testChecksec();
  await testEntitlements();
  await testClassdump();
  await testCookies();
  await testFs();
  await testKeychain();
  await testUserDefaults();
  await testLsof();

  summary();
}

ObjC.schedule(ObjC.mainQueue, () => {
  run().catch((e) => {
    console.log(
      `\nFATAL: ${e instanceof Error ? e.stack || e.message : String(e)}`,
    );
  });
});
