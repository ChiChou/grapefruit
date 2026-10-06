export type Frame = [[number, number], [number, number]];

export function intersection(a: Frame, b: Frame): Frame | null {
  const x = Math.max(a[0][0], b[0][0]);
  const y = Math.max(a[0][1], b[0][1]);
  const right = Math.min(a[0][0] + a[1][0], b[0][0] + b[1][0]);
  const bottom = Math.min(a[0][1] + a[1][1], b[0][1] + b[1][1]);
  return right > x && bottom > y ? [[x, y], [right - x, bottom - y]] : null;
}

export function valid(frame: Frame): boolean {
  return Array.isArray(frame) && frame.length === 2 &&
    frame.every(pair => Array.isArray(pair) && pair.length === 2 && pair.every(Number.isFinite)) &&
    frame[1].every(n => n >= 0);
}
