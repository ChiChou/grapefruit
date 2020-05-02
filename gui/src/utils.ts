export function * tokenize(text: string, delimiters: string): IterableIterator<string> {
  let left = 0
  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i)
    if (delimiters.includes(ch)) {
      if (left < i) yield text.substr(left, i - left)
      yield ch
      left = i + 1
    }
  }
  yield text.substr(left)
}

export function htmlescape(text: string) {
  const e = document.createElement('span')
  e.textContent = text
  return e.innerHTML
}

export function humanFileSize(size: number): string {
  if (isNaN(size)) return 'N/A'
  if (size === 0) return '0 kB'
  const i = Math.floor(Math.log(size) / Math.log(1024))
  const unit = ['bytes', 'kB', 'MB', 'GB', 'TB'][i]
  if (!unit) return 'N/A'
  const val = size / (1 << (10 * i))
  return parseFloat(val.toFixed(2)).toString() + ' ' + unit
}
