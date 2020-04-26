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
