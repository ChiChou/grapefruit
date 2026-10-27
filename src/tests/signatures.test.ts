import assert from "node:assert/strict";
import { test } from "node:test";
import { Catalog, moduleName, architecture } from "../lib/signatures.ts";
import { routes } from "../routes/signatures.ts";
import { display } from "../../gui/src/lib/signatures.ts";
import { asset } from "../lib/assets.ts";
import lock from "../../signatures.lock.json" with { type: "json" };

const path = asset("signatures", "signatures.db");

test("offline templates preserve C types and distinguish strings from pointers", () => {
  const db = new Catalog(path, lock.version);
  try {
    for (const platform of ["android", "darwin"] as const) {
      const module = platform === "android" ? "/apex/com.android.runtime/lib64/bionic/libc.so" : "/usr/lib/system/libsystem_c.dylib";
      const puts = db.lookup({ platform, arch: "arm64", module, name: "puts" });
      assert(puts);
      assert.equal(puts.nameOnly, false);
      assert.equal(puts.args[0].c, "const char *");
      assert.equal(puts.args[0].frida, "pointer");
      assert.equal(display(puts.args[0]), "char *");
      const malloc = db.lookup({ platform, arch: "arm64", module, name: "malloc" });
      assert(malloc);
      assert.equal(malloc.returns.frida, "pointer");
      assert.equal(display(malloc.returns), "pointer");
      assert.equal(malloc.args[0].c, "size_t");
      assert.equal(malloc.args[0].size, 8);
    }
    const narrow = db.lookup({ platform: "android", arch: "ia32", module: "libc.so", name: "malloc" });
    assert.equal(narrow?.args[0].size, 4);
    assert(db.lookup({ platform: "darwin", arch: "arm64e", module: "Security", name: "_SecItemCopyMatching" }));
    assert(db.lookup({ platform: "android", arch: "arm64", name: "sqlite3_open" }));
    assert(db.lookup({ platform: "android", arch: "arm64", name: "printf" })?.variadic);
    assert(db.lookup({ platform: "android", name: "puts", module: "custom.so" })?.nameOnly);
    assert.equal(db.lookup({ platform: "android", name: "igf_no_such_function" }), null);
    assert.equal(db.lookup({ platform: "android", name: "puts' OR 1=1 --" }), null);
    assert.equal(db.lookup({ platform: "android", name: "puts", arch: "mips" }), null);
  } finally { db.close(); }
});

test("signature lookup route validates input and preserves manual fallback", async () => {
  const db = new Catalog(path, lock.version);
  try {
    const app = routes(() => db);
    assert.equal((await app.request("/signatures?platform=bad&name=puts")).status, 400);
    assert.equal((await app.request("/signatures?platform=android")).status, 400);
    const found = await app.request("/signatures?platform=android&arch=arm64&module=libc.so&name=puts");
    assert.equal(found.status, 200);
    assert.equal((await found.json()).match.args[0].display, "utf8");
    const missing = await app.request("/signatures?platform=android&name=igf_unknown");
    assert.equal(missing.status, 200);
    assert.equal((await missing.json()).match, null);
  } finally { db.close(); }
  assert.throws(() => new Catalog(path, "wrong-version"), /pinned release/);
});

test("platform module and architecture aliases remain unambiguous", () => {
  assert.equal(moduleName("/System/Library/Frameworks/Security.framework/Security", "darwin"), "Security");
  assert.equal(moduleName("/usr/lib/libobjc.A.dylib", "darwin"), "libobjc");
  assert.equal(architecture("thumb"), "arm");
  assert.equal(architecture("x86_64"), "x64");
});
