import { NSHomeDirectory, NSTemporaryDirectory } from '../lib/foundation.js'
import { valueOf } from '../lib/dict.js'
import uuid from '../lib/uuid.js'
import { NSArray, NSDictionary, NSObject, NSString, StringLike, _Nullable } from '../objc-types.js'

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

const ATTR_KEYS_MAPPING = {
  uid: 'NSFileOwnerAccountID',
  owner: 'NSFileOwnerAccountName',
  size: 'NSFileSize',
  creation: 'NSFileCreationDate',
  permission: 'NSFilePosixPermissions',
  gid: 'NSFileGroupOwnerAccountID',
  type: 'NSFileType',
  group: 'NSFileGroupOwnerAccountName',
  modification: 'NSFileModificationDate',
  protection: 'NSFileProtectionKey'
} as const

const NSFileAttributeKeyValues = [...Object.values(ATTR_KEYS_MAPPING)]

type AttributeKey = keyof typeof ATTR_KEYS_MAPPING
type NSAttributeKey = typeof NSFileAttributeKeyValues[number]
type NSFileAttribute = NSDictionary<NSAttributeKey, NSObject>

type WithNSErrorChecker<T> = (err: NativePointer) => T

interface NSFileManager extends NSObject {
  contentsOfDirectoryAtPath_error_(path: StringLike, pError: NativePointer): NSArray<NSString>;
  fileExistsAtPath_isDirectory_(path: StringLike, pIsDir: NativePointer): boolean;
  attributesOfItemAtPath_error_(path: StringLike, pError: NativePointer): NSFileAttribute;
  removeItemAtPath_error_(path: StringLike, pError: NativePointer): boolean;
  moveItemAtPath_toPath_error_(src: StringLike, dst: StringLike, pError: NativePointer): boolean;
  copyItemAtPath_toPath_error_(src: StringLike, dst: StringLike, pError: NativePointer): boolean;
  createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
    path: StringLike, intermediate: boolean, attributes: _Nullable<NSFileAttribute>, pError: NativePointer): boolean;
}

function ok<T>(block: WithNSErrorChecker<T>) {
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const result = block(pError)
  const err = pError.readPointer()
  if (!err.isNull())
    throw new Error(new ObjC.Object(err).localizedDescription())
  return result
}

const fileManager = ObjC.classes.NSFileManager.defaultManager() as NSFileManager

function readdir(path: string, max = 500, folderOnly = false): Item[] {
  const list = ok(pError =>
    fileManager.contentsOfDirectoryAtPath_error_(path, pError))

  const pIsDir = Memory.alloc(Process.pointerSize)
  const count = list.count()
  const result = []
  const nsPath = ObjC.classes.NSString.stringWithString_(path) as NSString
  for (let i = 0, j = 0; i < count; i++) {
    const filename = list.objectAtIndex_(i)
    const absolute = nsPath.stringByAppendingPathComponent_(filename)
    pIsDir.writePointer(NULL)
    fileManager.fileExistsAtPath_isDirectory_(absolute, pIsDir)
    const isFile = pIsDir.readPointer().isNull()

    if (isFile && folderOnly) continue
    if (isFile && filename.toString().match(/^frida-([a-zA-z0-9]+)\.dylib$/)) continue
    if (j++ > max) break

    let attribute: Attributes | null = null
    try {
      attribute = attributes(absolute);
    } catch (e) {
      console.warn(`Eror: unable to get attribute of ${absolute}`)
      console.warn(`Reason: ${e}`)
    }

    const item: Item = {
      type: isFile ? 'file' : 'directory',
      name: filename.toString(),
      path: absolute.toString(),
      attribute,
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
  } else if (root === 'bundle' || root === '!') {
    prefix = ObjC.classes.NSBundle.mainBundle().bundlePath()
  } else {
    throw new Error('Invalid root')
  }

  return prefix.toString().replace(/\/$/, '') +
    (typeof path === 'string' ? '/' + path.replace(/^\//, '') : '')
}

export function ls(root: string, path = '') {
  const cwd = resolve(root, path)
  return {
    cwd,
    items: readdir(cwd)
  }
}

export function subdirs(root: string, path = '') {
  const cwd = resolve(root, path)
  return {
    cwd,
    items: readdir(cwd, 500, true)
  }
}

export function plist(path: string) {
  const info = ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path)
  if (!info)
    throw new Error(`"${path}" is not valid plist format`)
  return valueOf(info)
}

const NSUTF8StringEncoding = 4

export function write(path: string, text: string) {
  return ok(pError =>
    ObjC.classes.NSString.stringWithString_(text)
      .writeToFile_atomically_encoding_error_(path, NULL, NSUTF8StringEncoding, pError) as boolean)
}

export function remove(path: string) {
  return ok(pError =>
    fileManager.removeItemAtPath_error_(path, pError))
}

export function move(src: string, dst: string) {
  return ok(pError =>
    fileManager.moveItemAtPath_toPath_error_(src, dst, pError))
}

export function copy(src: string, dst: string) {
  return ok(pError =>
    fileManager.copyItemAtPath_toPath_error_(src, dst, pError))
}

export function text(path: string) {
  const SIZE = 1024 * 1024 // max read size: 1MB

  const handle = ObjC.classes.NSFileHandle.fileHandleForReadingAtPath_(path)
  if (!handle) throw new Error(`unable to open file ${path} for reading`)
  const data = handle.readDataUpToLength_error_(SIZE, NULL)
  handle.closeAndReturnError_(NULL)
  return ObjC.classes.NSString.alloc().initWithData_encoding_(data, NSUTF8StringEncoding).toString()
}

export function mkdir(path: string) {
  return ok(pError =>
    fileManager.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
      path, true, null, pError))
}

export function attributes(path: StringLike) {
  const dict = ok(pError => fileManager.attributesOfItemAtPath_error_(path, pError))
  const result: Partial<Attributes> = {}
  for (const [jsKey, ocKey] of Object.entries(ATTR_KEYS_MAPPING)) {
    const value = dict.objectForKey_(ocKey)
    result[jsKey as AttributeKey] = valueOf(value)
  }

  return result as Attributes
}

export async function download(path: string) {
  const session = uuid()
  const name = Memory.allocUtf8String(path)
  const watermark = 10 * 1024 * 1024
  const subject = 'download'

  const { size, type } = attributes(path)
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
