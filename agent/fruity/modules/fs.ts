import ObjC from "frida-objc-bridge";
import type { NSArray, NSString, NSFileManager, NSURL, StringLike, NSObject, NSDictionary} from "../typings.js";

import { valueOf } from '../bridge/dictionary.js'
import { NSHomeDirectory, NSTemporaryDirectory } from '../lib/foundation.js'
import uuid from '../lib/uuid.js'

const cf = Process.getModuleByName('CoreFoundation')
if (!cf) throw new Error('CoreFoundation is not loaded')

const foundation = Process.getModuleByName('Foundation')
if (!foundation) throw new Error('Foundation is not loaded')

const NSURL_RESOURCE_KEYS = {
  name: 'NSURLNameKey',
  isDir: 'NSURLIsDirectoryKey',
  protectionKey: 'NSURLFileProtectionKey',
  size: 'NSURLFileSizeKey',
  isAlias: 'NSURLIsAliasFileKey',
  creationDate: 'NSURLCreationDateKey',
  isLink: 'NSURLIsSymbolicLinkKey',
  isWritable: 'NSURLIsWritableKey',
}

const expectedKeys: NSArray<NSString> = ObjC.classes.NSMutableArray.new()
for (const value of Object.values(NSURL_RESOURCE_KEYS)) {
  const p = cf.findExportByName(value)
  if (!p) throw new Error(`Key ${value} not found`)
  expectedKeys.addObject_(p.readPointer())
}

const NS_FILE_ATTR_KEYS = {
  created: 'NSFileCreationDate',
  groupOwnerId: 'NSFileGroupOwnerAccountID',
  groupOwnerName: 'NSFileGroupOwnerAccountName',
  ownerId: 'NSFileOwnerAccountID',
  ownerName: 'NSFileOwnerAccountName',
  perm: 'NSFilePosixPermissions',
  protection: 'NSFileProtectionKey',
  size: 'NSFileSize',
  type: 'NSFileType',
}

const NSFileAttributeKeyLookup = Object.fromEntries(
  Object.entries(NS_FILE_ATTR_KEYS).map(([key, value]) =>
    [key, new ObjC.Object(foundation.findExportByName(value)!.readPointer()) as NSString])
)

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

const filemgr = ObjC.classes.NSFileManager.defaultManager() as NSFileManager

function throwsError<T>(fn: (pError: NativePointer, ...args: any[]) => T, ...args: any[]): T {
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL);
  const result = fn(pError, ...args)
  const err = pError.readPointer()
  if (!err.isNull())
    throw new Error(new ObjC.Object(err).localizedDescription())
  return result
}

export function ls(root: string, component = '') {
  function contentsOf(pError: NativePointer, url: NSURL) {
    const withHidden = false
    const NSDirectoryEnumerationSkipsHiddenFiles = 1 << 2
    const opt = withHidden ? 0 : NSDirectoryEnumerationSkipsHiddenFiles
    const result = filemgr.contentsOfDirectoryAtURL_includingPropertiesForKeys_options_error_(
      url, expectedKeys, opt, pError) as NSArray<NSURL>

    function convert(nsdict: NSDictionary<StringLike, NSObject>) {
      return Object.fromEntries(
        Object.entries(NSURL_RESOURCE_KEYS).map(
          ([jsKey, key]) => ([jsKey, valueOf(nsdict.objectForKey_(key))]))
      )
    }

    function* gen() {
      const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
      for (let i = 0; i < result.count(); i++) {
        const url = result.objectAtIndex_(i)
        const dict = url.resourceValuesForKeys_error_(expectedKeys, pError)
        const err = pError.readPointer()
        if (!err.isNull() || !dict)
          throw new Error((`Error reading resource values for ${url}, ${new ObjC.Object(err).localizedDescription()}`))

        for (const [jsKey, key] of Object.entries(NSURL_RESOURCE_KEYS)) {
          const value = dict.objectForKey_(key)
          if (!value) continue
        }

        yield convert(dict)
      }
    }

    return [...gen()]
  }

  const cwd = resolve(root, component)
  return throwsError(contentsOf, ObjC.classes.NSURL.fileURLWithPath_(cwd))
}

export function rm(path: string) {
  return throwsError((pError, path) => {
    const url = ObjC.classes.NSURL.fileURLWithPath_(path)
    return filemgr.removeItemAtURL_error_(url, pError)
  }, path)
}

export function cp(src: string, dst: string) {
  return throwsError((pError, src, dst) => {
    const srcUrl = ObjC.classes.NSURL.fileURLWithPath_(src)
    const dstUrl = ObjC.classes.NSURL.fileURLWithPath_(dst)
    return filemgr.copyItemAtURL_toURL_error_(srcUrl, dstUrl, pError)
  }, src, dst)
}

export function mv(src: string, dst: string) {
  return throwsError((pError, src, dst) => {
    const srcUrl = ObjC.classes.NSURL.fileURLWithPath_(src)
    const dstUrl = ObjC.classes.NSURL.fileURLWithPath_(dst)
    return filemgr.moveItemAtURL_toURL_error_(srcUrl, dstUrl, pError)
  }, src, dst)
}

export function attr(path: string) {
  // return filemgr.attr(path)
}

export function plist(path: string) {
  return ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path)
}

const NSUTF8StringEncoding = 4

export function text(path: string) {
  return ObjC.classes.NSString
    .stringWithContentsOfFile_encoding_error_(path, NSUTF8StringEncoding, NULL).toString()
}

// export function writeText(path: string, text: string) {
//   return ObjC.classes.NSString.stringWithString_(text)
//     .writeToFile_atomically_encoding_error_(path, NULL, NSUTF8StringEncoding, NULL)
// }

export async function download(path: string) {
  const session = uuid()
  // const name = Memory.allocUtf8String(path)
  // const watermark = 10 * 1024 * 1024
  // const subject = 'download'

  // const { size, type } = attr(path)
  // if (type && type.toString() === 'NSFileTypeDirectory') {
  //   throw new Error(`${path} is a directory`)
  // }

  // const fd = open(name, 0, 0) as number
  // if (fd === -1) throw new Error(`unable to open file ${path}`)

  // send({ subject, event: 'begin', session, path, size })
  // setImmediate(async () => {
  //   const stream = new UnixInputStream(fd, { autoClose: true })
  //   let eof = false
  //   while (!eof) {
  //     const buf = await stream.read(watermark)
  //     eof = (buf.byteLength > 0 && buf.byteLength < watermark)
  //     send({ subject, event: 'data', session }, buf)
  //     await new Promise(resolve => recv('ack', resolve))
  //   }
  //   send({ subject, event: 'end', session })
  // })

  return session
}
