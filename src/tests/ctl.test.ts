import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { describe, it, mock } from "node:test";

import { Sessions } from "../daemon/sessions.ts";

const exec = promisify(execFile);
const removed = [
  "script.evaluate",
  "memory.dump",
  "memory.scan",
  "threads.list",
  "symbol.modules",
  "symbol.exports",
  "info.processInfo",
  "webview.evaluate",
  "jsc.run",
  "rn.inject",
];

describe("CLI RPC scope", () => {
  it("rejects removed RPCs before target validation or daemon startup", async () => {
    for (const spec of removed) {
      await assert.rejects(
        exec(process.execPath, ["src/bin.ts", "rpc", spec]),
        (error: Error & { stderr?: string }) => {
          assert.match(error.stderr ?? "", /is not part of the IGF CLI/);
          assert.doesNotMatch(error.stderr ?? "", /--device is required/);
          return true;
        },
      );
    }
  });

  it("rejects direct daemon RPCs without acquiring a Frida session", async () => {
    const sessions = new Sessions();
    const acquire = mock.method(sessions, "acquire", () => {
      throw new Error("session acquisition reached");
    });
    try {
      for (const spec of removed) {
        const [ns, method] = spec.split(".");
        await assert.rejects(sessions.rpc({}, ns, method, []), /is not part of the IGF CLI/);
      }
      assert.equal(acquire.mock.callCount(), 0);

      for (const spec of ["pins.start", "sqlite.dump", "keychain.list", "symbol.strings"]) {
        const [ns, method] = spec.split(".");
        await assert.rejects(sessions.rpc({}, ns, method, []), /session acquisition reached/);
      }
      assert.equal(acquire.mock.callCount(), 4);
    } finally {
      acquire.mock.restore();
      await sessions.shutdown();
    }
  });
});
