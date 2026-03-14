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
import * as checksec from "./modules/checksec/index.js";
import * as entitlements from "./modules/entitlements.js";
import * as classdump from "./modules/classdump.js";
import * as cookies from "./modules/cookies.js";
import * as fs from "./modules/fs.js";
import * as keychain from "./modules/keychain.js";
import * as userdefaults from "./modules/userdefaults.js";
import * as lsof from "./modules/lsof.js";
import * as plugins from "./modules/plugins.js";
import * as uidevice from "./modules/uidevice.js";
import * as ui from "./modules/ui.js";
import * as webview from "./modules/webview.js";
import * as jsc from "./modules/jsc.js";
import * as rn from "./modules/rn.js";
import * as assetcatalog from "./modules/assetcatalog.js";

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
    assertKeys(
      p as unknown as Record<string, unknown>,
      ["xml", "value"],
      "plist",
    );
    assertType(p.xml, "string", "xml");
    assert(p.xml.length > 0, "xml should be non-empty");
    assertType(p.value, "object", "value");
    const dict = p.value as Record<string, unknown>;
    assert(
      "CFBundleIdentifier" in dict,
      "plist.value should contain CFBundleIdentifier",
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

  await test("checksec.main returns MachO security flags", async () => {
    const r = checksec.main();
    assertKeys(
      r as unknown as Record<string, unknown>,
      [
        "pie",
        "nx",
        "canary",
        "arc",
        "rpath",
        "codesign",
        "encryption",
        "stripped",
        "fortify",
        "pac",
      ],
      "checksec.main",
    );
    assertType(r.pie, "boolean", "pie");
    assertType(r.canary, "boolean", "canary");
    assertType(r.arc, "boolean", "arc");
    assertArray(r.rpath, "rpath");
    assertType(r.codesign, "boolean", "codesign");
    assertType(r.stripped, "boolean", "stripped");
    assertKeys(
      r.fortify as unknown as Record<string, unknown>,
      ["fortified", "fortifiable"],
      "fortify",
    );
    console.log(
      `    pie=${r.pie} nx=${r.nx} canary=${r.canary} arc=${r.arc} codesign=${r.codesign}`,
    );
    console.log(
      `    encryption=${r.encryption} stripped=${r.stripped} pac=${r.pac}`,
    );
    console.log(
      `    fortify: ${r.fortify.fortified}/${r.fortify.fortifiable}`,
    );
  });

  await test("checksec.all returns array of results", async () => {
    const all = checksec.all();
    assertArray(all, "all");
    assertNonEmpty(all, "all");
    assertType(all[0].pie, "boolean", "first.pie");
    console.log(`    ${all.length} modules checked`);
  });

  await test("checksec.single returns result for named module", async () => {
    const [main] = Process.enumerateModules();
    const r = checksec.single(main.name);
    assert(r !== undefined, "should find main module by name");
    assertType(r!.pie, "boolean", "pie");
    console.log(`    checked ${main.name}: pie=${r!.pie}`);
  });

  await test("checksec.single returns undefined for unknown module", async () => {
    const r = checksec.single("__nonexistent_module_12345__");
    assert(r === undefined, "should return undefined for unknown module");
    console.log("    correctly returned undefined");
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

  await test("classdump.inheritance returns superclass mapping", async () => {
    const map = classdump.inheritance();
    assertType(map, "object", "inheritance");
    const keys = Object.keys(map);
    assertNonEmpty(keys, "inheritance keys");
    assert(map["NSObject"] === null, "NSObject superclass should be null");
    console.log(`    ${keys.length} classes in inheritance map`);
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
      [
        "uid",
        "gid",
        "perm",
        "size",
        "type",
        "owner",
        "group",
        "created",
        "protection",
      ],
      "attrs",
    );
    assertType(a.uid, "number", "uid");
    assertType(a.gid, "number", "gid");
    assertType(a.perm, "number", "perm");
    assertType(a.size, "number", "size");
    assertType(a.owner, "string", "owner");
    assertType(a.group, "string", "group");
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

  await test("fs.mkdirp creates nested directories", async () => {
    const ts = Date.now();
    const topDir = home + "/igf_mkdirp_test_" + ts;
    const testDir = topDir + "/sub/dir";
    fs.mkdirp(testDir);

    const result = fs.ls(testDir);
    assertType(result.cwd, "string", "cwd");
    console.log(`    created ${testDir}`);

    // cleanup
    fs.rm(topDir);
    console.log("    cleaned up test directory");
  });

  await test("fs.access checks path writability", async () => {
    const writable = fs.access(home);
    assertType(writable, "boolean", "access");
    console.log(`    home writable=${writable}`);

    const bundleWritable = fs.access(bundle);
    assertType(bundleWritable, "boolean", "bundle access");
    console.log(`    bundle writable=${bundleWritable}`);
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

async function testPlugins() {
  console.log("\n--- plugins ---");

  await test("plugins.list returns array of plugin info", async () => {
    const items = plugins.list();
    assertArray(items, "list");
    console.log(`    ${items.length} plugins`);
    if (items.length > 0) {
      const first = items[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        [
          "identifier",
          "extensionPoint",
          "displayName",
          "version",
          "path",
          "uuid",
        ],
        "plugin entry",
      );
      assertType(first.identifier, "string", "identifier");
      assertType(first.path, "string", "path");
      console.log(
        `    first: id=${first.identifier} name=${first.displayName}`,
      );
    }
  });
}

async function testUIDevice() {
  console.log("\n--- uidevice ---");

  await test("uidevice.info returns device info fields", async () => {
    const d = uidevice.info();
    assertKeys(
      d as unknown as Record<string, unknown>,
      [
        "name",
        "model",
        "localizedModel",
        "systemName",
        "systemVersion",
        "identifierForVendor",
        "batteryLevel",
        "batteryState",
        "userInterfaceIdiom",
        "isMultitaskingSupported",
      ],
      "uidevice.info",
    );
    assertType(d.name, "string", "name");
    assertType(d.model, "string", "model");
    assertType(d.systemName, "string", "systemName");
    assertType(d.systemVersion, "string", "systemVersion");
    assertType(d.batteryLevel, "number", "batteryLevel");
    assertType(d.batteryState, "string", "batteryState");
    assertType(d.isMultitaskingSupported, "boolean", "isMultitaskingSupported");
    console.log(`    ${d.name} ${d.model} ${d.systemName} ${d.systemVersion}`);
    console.log(
      `    battery=${d.batteryLevel} state=${d.batteryState} idiom=${d.userInterfaceIdiom}`,
    );
  });
}

async function testUI() {
  console.log("\n--- ui ---");

  await test("ui.dump returns view hierarchy", async () => {
    const tree = await ui.dump();
    assert(tree !== null, "dump should return a node");
    if (tree) {
      assertKeys(
        tree as unknown as Record<string, unknown>,
        ["clazz", "children", "frame"],
        "UIDumpNode",
      );
      assertType(tree.clazz, "string", "clazz");
      assertArray(tree.children!, "children");
      console.log(`    root: ${tree.clazz} children=${tree.children!.length}`);
    }
  });

  skip("ui.highlight", "side-effect: modifies UI overlay");
  skip("ui.dismissHighlight", "side-effect: modifies UI overlay");
}

async function testWebview() {
  console.log("\n--- webview ---");

  await test("webview.listWK returns array of WKWebView info", async () => {
    const views = await webview.listWK();
    assertArray(views, "listWK");
    console.log(`    ${views.length} WKWebView instances`);
    if (views.length > 0) {
      const first = views[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["handle", "kind", "js", "jsAutoOpenWindow"],
        "WKWebViewInfo",
      );
      assertType(first.handle, "string", "handle");
      assert(first.kind === "WK", `kind should be WK, got ${first.kind}`);
      assertType(first.js, "boolean", "js");
      console.log(
        `    first: handle=${first.handle} url=${first.url ?? "(none)"} js=${first.js}`,
      );
    }
  });

  await test("webview.listUI returns array of UIWebView info", async () => {
    const views = await webview.listUI();
    assertArray(views, "listUI");
    console.log(`    ${views.length} UIWebView instances`);
    if (views.length > 0) {
      const first = views[0];
      assertKeys(
        first as unknown as Record<string, unknown>,
        ["handle", "kind"],
        "UIWebViewInfo",
      );
      assert(first.kind === "UI", `kind should be UI, got ${first.kind}`);
      console.log(
        `    first: handle=${first.handle} url=${first.url ?? "(none)"}`,
      );
    }
  });

  skip("webview.evaluate", "requires active webview handle");
  skip("webview.navigate", "side-effect: navigates webview");
}

async function testJsc() {
  console.log("\n--- jsc ---");

  await test("jsc.list returns JSContext map", async () => {
    const contexts = jsc.list();
    assertType(contexts, "object", "list");
    const handles = Object.keys(contexts);
    console.log(`    ${handles.length} JSContext instances`);
    if (handles.length > 0) {
      const first = handles[0];
      assertType(contexts[first], "string", "context description");
      console.log(`    first: handle=${first}`);
    }
  });

  skip("jsc.dump", "requires active JSContext handle");
  skip("jsc.run", "side-effect: executes code in JSContext");
}

async function testRn() {
  console.log("\n--- rn ---");

  await test("rn.arch returns architecture flags", async () => {
    const a = rn.arch();
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
    const instances = rn.list();
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

async function testAssetCatalog() {
  console.log("\n--- assetcatalog ---");

  await test("assetcatalog.open returns catalog info", async () => {
    const { bundle } = fs.roots();
    const catalogPath = bundle + "/Assets.car";
    let threw = false;
    try {
      const catalog = assetcatalog.open(catalogPath);
      assertKeys(
        catalog as unknown as Record<string, unknown>,
        ["path", "names"],
        "assetcatalog.open",
      );
      assertType(catalog.path, "string", "path");
      assertArray(catalog.names, "names");
      console.log(`    ${catalog.names.length} assets in catalog`);
      if (catalog.names.length > 0) {
        console.log(`    first: ${catalog.names[0]}`);
      }
    } catch (_) {
      threw = true;
      console.log("    Assets.car not found (expected for some apps)");
    }
  });

  await test("assetcatalog.variants returns variant info", async () => {
    const { bundle } = fs.roots();
    const catalogPath = bundle + "/Assets.car";
    let threw = false;
    try {
      const catalog = assetcatalog.open(catalogPath);
      if (catalog.names.length === 0) {
        console.log("    (no assets to inspect, skipping)");
        return;
      }
      const vars = assetcatalog.variants(catalogPath, catalog.names[0]);
      assertArray(vars, "variants");
      if (vars.length > 0) {
        const first = vars[0];
        assertKeys(
          first as unknown as Record<string, unknown>,
          ["index", "scale", "width", "height", "isVector", "isTemplate", "hasSliceInfo", "uti"],
          "AssetVariant",
        );
        assertType(first.index, "number", "index");
        assertType(first.scale, "number", "scale");
        assertType(first.isVector, "boolean", "isVector");
        console.log(
          `    ${vars.length} variants for ${catalog.names[0]}: ${first.width}x${first.height} @${first.scale}x`,
        );
      } else {
        console.log(`    no variants for ${catalog.names[0]}`);
      }
    } catch (_) {
      threw = true;
      console.log("    Assets.car not found (expected for some apps)");
    }
  });

  skip("assetcatalog.image", "heavy: extracts and encodes images");
  skip("assetcatalog.rawImage", "heavy: extracts raw image data");
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
  await testPlugins();
  await testUIDevice();
  await testUI();
  await testWebview();
  await testJsc();
  await testRn();
  await testAssetCatalog();

  // side-effect only modules (no safe read-only API)
  console.log("\n--- geolocation ---");
  skip("geolocation.fake", "side-effect: fakes GPS location");
  skip("geolocation.dismiss", "side-effect: removes location hooks");

  console.log("\n--- url ---");
  skip("url.open", "side-effect: triggers URL handler");

  summary();
}

ObjC.schedule(ObjC.mainQueue, () => {
  run().catch((e) => {
    console.log(
      `\nFATAL: ${e instanceof Error ? e.stack || e.message : String(e)}`,
    );
  });
});
