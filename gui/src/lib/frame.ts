export type Box = [number, number, number, number];
export type Edge = { x: -1 | 0 | 1; y: -1 | 0 | 1 };

export function shift(box: Box, dx: number, dy: number, edge?: Edge): Box {
  let [x, y, width, height] = box;
  if (!edge) return [x + dx, y + dy, width, height];
  if (edge.x === 1) width = Math.max(0, width + dx);
  if (edge.y === 1) height = Math.max(0, height + dy);
  if (edge.x === -1) {
    const left = Math.min(x + dx, x + width);
    width += x - left;
    x = left;
  }
  if (edge.y === -1) {
    const top = Math.min(y + dy, y + height);
    height += y - top;
    y = top;
  }
  return [x, y, width, height];
}
