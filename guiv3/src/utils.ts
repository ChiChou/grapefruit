export function isSystemDark() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches
}
