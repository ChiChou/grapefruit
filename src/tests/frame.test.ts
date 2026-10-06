import assert from "node:assert/strict";
import { test } from "node:test";
import { shift } from "../../gui/src/lib/frame.ts";

test("moving a frame preserves size and supports negative coordinates", () => {
  const box: [number, number, number, number] = [10, 20, 30.123456, 40];
  assert.deepEqual(shift(box, -25, 7), [-15, 27, 30.123456, 40]);
  assert.deepEqual(box, [10, 20, 30.123456, 40]);
});

test("resizing the far corner keeps the origin fixed and clamps size", () => {
  assert.deepEqual(shift([10, 20, 30, 40], 5, -60, { x: 1, y: 1 }), [10, 20, 35, 0]);
});

test("resizing the near corner anchors the opposite edges", () => {
  assert.deepEqual(shift([10, 20, 30, 40], -5, 10, { x: -1, y: -1 }), [5, 30, 35, 30]);
  assert.deepEqual(shift([10, 20, 30, 40], 50, 70, { x: -1, y: -1 }), [40, 60, 0, 0]);
});

test("edge resizing leaves the other axis untouched", () => {
  assert.deepEqual(shift([10, 20, 30, 40], 5, 100, { x: 1, y: 0 }), [10, 20, 35, 40]);
  assert.deepEqual(shift([10, 20, 30, 40], 100, -5, { x: 0, y: -1 }), [10, 15, 30, 45]);
});
