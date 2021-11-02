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

export function htmlescape(text: string): string {
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

export function extname(name: string): string {
  const lastIndex = name.lastIndexOf('.')
  if (lastIndex) return name.substr(lastIndex + 1).toLowerCase()
  return name
}

export function basename(name: string): string {
  const lastIndex = name.lastIndexOf('/')
  if (lastIndex) return name.substr(lastIndex + 1)
  return name
}

export function icon(name: string): string {
  const lastIndex = name?.lastIndexOf('.')
  const mapping: { [key: string]: string } = {
    pdf: 'file-pdf-outline',
    js: 'language-javascript',
    plist: 'cog-box',
    dylib: 'cogs',
    svg: 'xml',
    xml: 'xml',
    entitlements: 'xml',
    json: 'code-json',
    binarycookies: 'cookie'
  }

  const ext = extname(name)
  if (ext && ext.length) {
    const ext = name.substr(lastIndex + 1).toLowerCase()
    if (Object.prototype.hasOwnProperty.call(mapping, ext)) return mapping[ext]

    if (/^(jpe?g|png|gif|webp)$/.exec(ext)) return 'file-image-outline'
    if (/^html?$/.exec(ext)) return 'xml'
    if (/^docx?$/.exec(ext)) return 'file-word-outline'
    if (/^(xlsx?|csv)$/.exec(ext)) return 'file-excel-outline'

    if (['txt', 'log', 'glsl'].includes(ext)) return 'file-document-outline'
    if (['wav', 'mp3', 'aac', 'm4a'].includes(ext)) return 'file-music-outline'
    if (['mp4', 'mov', 'avi', 'webm'].includes(ext)) return 'file-video-outline'
    if (['db', 'sqlite', 'localstorage'].includes(ext)) return 'database'
  }

  return 'file-outline'
}

export function filetype(name: string): string {
  const mapping: { [key: string]: string } = {
    pdf: 'pdf',
    plist: 'plist',
    strings: 'plist',
    binarycookies: 'cookiejar'
  }

  const ext = extname(name)
  if (ext && ext.length) {
    if (Object.prototype.hasOwnProperty.call(mapping, ext)) return mapping[ext]

    if (/^(jpe?g|png|gif|webp|svg)$/.exec(ext)) return 'image'
    if (/^html?$/.exec(ext)) return 'text'

    if (['txt', 'log', 'csv', 'js', 'xml', 'json', 'py', 'sql', 'glsl', 'entitlements', 'css'].includes(ext)) return 'text'
    if (['wav', 'mp3', 'aac', 'm4a'].includes(ext)) return 'audio'
    if (['mp4', 'mov', 'avi', 'webm'].includes(ext)) return 'video'
    if (['db', 'sqlite', 'localstorage'].includes(ext)) return 'database'
  }

  return 'hex'
}

export function rem2px(factor: number): number {
  return factor * parseFloat(getComputedStyle(document.documentElement).fontSize)
}

const PREFIX = 'OBJC_CLASS_$_'

export function isClass(name: string): boolean {
  return name.startsWith(PREFIX)
}

export function className(name: string): string {
  if (isClass(name)) return name.substring(PREFIX.length)
  throw new Error(`${name} is not an Objective-C class`)
}

export function render(template: string, vars: { [key: string]: string }): string {
  return template.replace(/\{\{ (\w+) \}\}/g, (substr, token) => vars[token])
}
