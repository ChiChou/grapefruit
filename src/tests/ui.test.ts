import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { intersection, valid } from "../../agent/src/fruity/lib/geometry.ts";

describe("UI clipping", () => {
  it("clips a scrolled child to its parent's visible region", () => {
    assert.deepEqual(intersection([[10, -30], [100, 100]], [[0, 0], [80, 200]]), [[10, 0], [70, 70]]);
  });

  it("excludes offscreen, touching and zero-sized rectangles", () => {
    for (const frame of [ [[100, 0], [20, 20]], [[-20, 0], [20, 20]], [[0, 0], [0, 20]] ] as const) {
      assert.equal(intersection([[...frame[0]], [...frame[1]]], [[0, 0], [100, 100]]), null);
    }
  });

  it("preserves nested clipping and nonzero window origins", () => {
    const parent = intersection([[20, 40], [200, 200]], [[10, 20], [100, 100]])!;
    assert.deepEqual(intersection([[30, 50], [200, 200]], parent), [[30, 50], [80, 70]]);
  });
});

describe("UI frame edits", () => {
  it("allows negative origins and zero dimensions", () => {
    assert.equal(valid([[-10, 20], [0, 40]]), true);
  });

  it("rejects malformed frames, nonfinite values and negative sizes", () => {
    for (const value of [null, [], [[], []], [[0, 0], [10, -1]], [[0, NaN], [1, 1]], [[0, 0], [Infinity, 1]], [["0", 0], [1, 1]]]) {
      assert.equal(valid(value as Parameters<typeof valid>[0]), false);
    }
  });
});
