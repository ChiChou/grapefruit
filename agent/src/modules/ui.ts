export function dump(): string {
  const win = ObjC.classes.UIWindow.keyWindow()
  if (!win) return ''
  return win.recursiveDescription().toString()
}
