import { NSString, StringLike, _Nullable } from '../bridge/foundation.js'
import { NSHomeDirectory, NSTemporaryDirectory } from '../lib/foundation.js'
import uuid from '../lib/uuid.js'

import filemgr from '../bridge/filemanager.js'
import { expose } from '../registry.js'

const open = new NativeFunction(Module.findExportByName(null, 'open')!, 'int', ['pointer', 'int', 'int'])

export interface Item {
  type: 'file' | 'directory' | 'symlink';
  name: string;
  path: string;
  attribute: Attributes | null;
}

export interface Attributes {
  uid: number;
  owner: string;
  size: number;
  creation: number;
  permission: number;
  gid: number;
  type?: string;
  group: string;
  modification: number;
  protection: string;
}

function resolve(root: string, component?: StringLike): NSString {
  let prefix: NSString
  if (root === 'tmp') {
    prefix = NSTemporaryDirectory()
  } else if (root === 'home' || root === '~') {
    prefix = NSHomeDirectory()
  } else if (root === 'bundle' || root === '!') {
    prefix = ObjC.classes.NSBundle.mainBundle().bundlePath()
  } else {
    throw new Error('Invalid root')
  }

  if (component)
    return prefix.stringByAppendingPathComponent_(component)

  return prefix
}

export function expand(root: string, component?: string) {
  return resolve(root, component).toString()
}

export function ls(root: string, component = '') {
  const cwd = resolve(root, component)
  const url = ObjC.classes.NSURL.fileURLWithPath_(cwd)
  return filemgr.contentsOf(url)
}

export function rm(path: string) {
  return filemgr.rm(path)
}

export function cp(src: string, dst: string) {
  return filemgr.cp(src, dst)
}

export function mv(src: string, dst: string) {
  return filemgr.mv(src, dst)
}

export function attr(path: string) {
  return filemgr.attr(path)
}

export function plist(path: string) {
  return ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path)
}

const NSUTF8StringEncoding = 4

export function text(path: string) {
  return ObjC.classes.NSString
    .stringWithContentsOfFile_encoding_error_(path, NSUTF8StringEncoding, NULL).toString()
}

export function writeText(path: string, text: string) {
  return ObjC.classes.NSString.stringWithString_(text)
    .writeToFile_atomically_encoding_error_(path, NULL, NSUTF8StringEncoding, NULL)
}

export async function download(path: string) {
  const session = uuid()
  const name = Memory.allocUtf8String(path)
  const watermark = 10 * 1024 * 1024
  const subject = 'download'

  const { size, type } = attr(path)
  if (type && type.toString() === 'NSFileTypeDirectory') {
    throw new Error(`${path} is a directory`)
  }

  const fd = open(name, 0, 0) as number
  if (fd === -1) throw new Error(`unable to open file ${path}`)

  send({ subject, event: 'begin', session, path, size })
  setImmediate(async () => {
    const stream = new UnixInputStream(fd, { autoClose: true })
    let eof = false
    while (!eof) {
      const buf = await stream.read(watermark)
      eof = (buf.byteLength > 0 && buf.byteLength < watermark)
      send({ subject, event: 'data', session }, buf)
      await new Promise(resolve => recv('ack', resolve))
    }
    send({ subject, event: 'end', session })
  })

  return session
}

expose('fs', {
  expand,
  ls,
  rm,
  cp,
  mv,
  attr,
  plist,
  text,
  writeText,
  download,
})
