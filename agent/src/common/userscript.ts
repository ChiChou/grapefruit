// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function evaluate(source: string, name?: string): any {
  // todo: how do we bridge ObjC?
  return Script.evaluate(name || "userscript", source);
}
