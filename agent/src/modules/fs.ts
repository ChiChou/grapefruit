import { NSHomeDirectory, NSTemporaryDirectory, attrs } from '../lib/foundation'
import { open } from '../lib/libc'
import { valueOf } from '../lib/dict'

const { NSBundle, NSFileManager, NSString, NSDictionary } = ObjC.classes

type ErrCallback = (err: NativePointer) => ObjC.Object

interface File {
  type: 'file' | 'directory';
  name: string;
  path: string;
  attribute: object; // todo: Attribute
}

function successful(block: ErrCallback) {
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const result = block(pError)
  const err = pError.readPointer()
  if (!err.isNull())
    throw new Error(new ObjC.Object(err).localizedDescription())
  return result
}

export function readdir(path: string, max=500): File[] {
  const list = successful(pError =>
    NSFileManager.defaultManager().contentsOfDirectoryAtPath_error_(path, pError))

  const pIsDir = Memory.alloc(Process.pointerSize)
  const count = list.count()
  const result = []
  const nsPath = NSString.stringWithString_(path)
  for (let i = 0, j = 0; i < count; i++) {
    const filename = list.objectAtIndex_(i)
    const absolute = nsPath.stringByAppendingPathComponent_(filename)
    pIsDir.writePointer(NULL)
    NSFileManager.defaultManager().fileExistsAtPath_isDirectory_(absolute, pIsDir)
    const isFile = pIsDir.readPointer().isNull()

    // if (isFile && filename.toString().match(/^frida-([a-zA-z0-9]+)\.dylib$/)) continue
    if (j++ > max) break

    const item: File = {
      type: isFile ? 'file' : 'directory',
      name: filename.toString(),
      path: absolute.toString(),
      attribute: attrs(absolute) || {}
    }

    result.push(item)
  }

  return result
}

export function resolve(root: string, path = '') {
  let prefix: string
  if (root === 'tmp') {
    prefix = NSTemporaryDirectory()
  } else if (root === 'home' || root === '~') {
    prefix = NSHomeDirectory()
  } else if (root === 'bundle') {
    prefix = NSBundle.mainBundle().bundlePath()
  } else {
    throw new Error('Invalid root')
  }

  return prefix.toString().replace(/\/$/, '') + '/' + path.replace(/^\//, '')
}

export function ls(root: string, path = '') {
  const cwd = resolve(root, path)
  return {
    cwd,
    items: readdir(cwd)
  }
}

export function plist(path: string) {
  const info = NSDictionary.dictionaryWithContentsOfFile_(path)
  if (!info)
    throw new Error(`"${path}" is not valid plist format`)
  return valueOf(info)
}

export function write(path: string, text: string) {
  const NSUTF8StringEncoding = 4
  return successful(pError =>
    NSString.stringWithString_(text)
      .writeToFile_atomically_encoding_error_(path, NULL, NSUTF8StringEncoding, pError))
}

export function remove(path: string) {
  return successful(pError =>
    NSFileManager.defaultManager().removeItemAtPath_error_(path, pError))
}

export function move(src: string, dst: string) {
  return successful(pError =>
    NSFileManager.defaultManager().moveItemAtPath_toPath_error_(src, dst, pError))
}

export function copy(src: string, dst: string) {
  return successful(pError =>
    NSFileManager.defaultManager().copyItemAtPath_toPath_error_(src, dst, pError))
}

export async function text(path: string) {
  const name = Memory.allocUtf8String(path)
  const SIZE = 10 * 1024 // max read size: 10k
  const fd = open(name, 0, 0) as number
  if (fd === -1) throw new Error(`unable to open file ${path}`)

  const stream = new UnixInputStream(fd, { autoClose: true })
  return stream.read(SIZE)
}

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0, v = c === 'x' ? r : ((r & 0x3) | 0x8)
    return v.toString(16)
  })
}

export async function download(path: string) {
  const session = uuidv4()
  const name = Memory.allocUtf8String(path)
  const watermark = 10 * 1024 * 1024
  const subject = 'download'

  const { size } = attrs(path)
  const fd = open(name, 0, 0) as number
  if (fd === -1)
    throw new Error(`unable to open file ${path}`)

  send({ subject, event: 'start', session, path, size })
  const stream = new UnixInputStream(fd, { autoClose: true })
  let eof = false
  while (!eof) {
    const buf = await stream.read(watermark)
    eof = (buf.byteLength > 0 && buf.byteLength < watermark)
    send({ subject, event: 'data', session }, buf)
  }
  send({ subject, event: 'finish', session })
}
