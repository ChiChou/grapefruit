import ObjC from "frida-objc-bridge";
import type {
  NSArray,
  NSString,
  NSFileManager,
  NSURL,
  StringLike,
  NSObject,
  NSDictionary,
} from "../typings.js";

import { valueOf } from "../bridge/dictionary.js";
import { NSHomeDirectory, NSTemporaryDirectory } from "../lib/foundation.js";

export interface Item {
  type: "file" | "directory" | "symlink";
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
  let prefix: NSString;
  if (root === "tmp") {
    prefix = NSTemporaryDirectory();
  } else if (root === "home" || root === "~") {
    prefix = NSHomeDirectory();
  } else if (root === "bundle" || root === "!") {
    prefix = ObjC.classes.NSBundle.mainBundle().bundlePath();
  } else {
    throw new Error(`Invalid root: ${JSON.stringify(root)}`);
  }

  if (component) return prefix.stringByAppendingPathComponent_(component);

  return prefix;
}

export function expand(root: string, component?: string) {
  return resolve(root, component).toString();
}

function shared() {
  return ObjC.classes.NSFileManager.defaultManager() as NSFileManager;
}

function throwsError<Args extends unknown[], T>(
  fn: (pError: NativePointer, ...args: Args) => T,
  ...args: Args
): T {
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL);
  const result = fn(pError, ...args);
  const err = pError.readPointer();
  if (!err.isNull())
    throw new Error(new ObjC.Object(err).localizedDescription());
  return result;
}

interface MetaData {
  name: string;
  dir: boolean;
  protection: string | null;
  size: number | null;
  alias: boolean;
  created: Date;
  symlink: boolean;
  writable: boolean;
}

function contentsOf(pError: NativePointer, url: NSURL) {
  const NSURL_RESOURCE_KEYS = {
    name: "NSURLNameKey",
    dir: "NSURLIsDirectoryKey",
    protection: "NSURLFileProtectionKey",
    size: "NSURLFileSizeKey",
    alias: "NSURLIsAliasFileKey",
    created: "NSURLCreationDateKey",
    symlink: "NSURLIsSymbolicLinkKey",
    writable: "NSURLIsWritableKey",
  } as const;

  const cf = Process.getModuleByName("CoreFoundation");
  const expectedKeys: NSArray<NSString> = ObjC.classes.NSMutableArray.new();
  for (const value of Object.values(NSURL_RESOURCE_KEYS)) {
    const p = cf.getExportByName(value);
    expectedKeys.addObject_(p.readPointer());
  }

  const withHidden = false;
  const NSDirectoryEnumerationSkipsHiddenFiles = 1 << 2;
  const opt = withHidden ? 0 : NSDirectoryEnumerationSkipsHiddenFiles;
  const result =
    shared().contentsOfDirectoryAtURL_includingPropertiesForKeys_options_error_(
      url,
      expectedKeys,
      opt,
      pError,
    ) as NSArray<NSURL>;

  function convert(nsdict: NSDictionary<StringLike, NSObject>) {
    return Object.fromEntries(
      Object.entries(NSURL_RESOURCE_KEYS).map(([jsKey, key]) => [
        jsKey,
        valueOf(nsdict.objectForKey_(key)),
      ]),
    ) as MetaData;
  }

  function* gen() {
    const pError = Memory.alloc(Process.pointerSize).writePointer(NULL);
    for (let i = 0; i < result.count(); i++) {
      const url = result.objectAtIndex_(i);
      const dict = url.resourceValuesForKeys_error_(expectedKeys, pError);
      const err = pError.readPointer();
      if (!err.isNull())
        throw new Error(
          `Error reading resource values for ${url}, ${new ObjC.Object(err).localizedDescription()}`,
        );

      if (dict) yield convert(dict);
    }
  }

  return [...gen()];
}

export function ls(root: string, component = "") {
  const cwd = resolve(root, component);
  return throwsError(contentsOf, ObjC.classes.NSURL.fileURLWithPath_(cwd));
}

export function rm(path: string) {
  return throwsError((pError, path) => {
    return shared().removeItemAtPath_error_(path, pError);
  }, path);
}

export function cp(src: string, dst: string) {
  return throwsError(
    (pError, src, dst) => {
      return shared().copyItemAtPath_toPath_error_(src, dst, pError);
    },
    src,
    dst,
  );
}

export function mv(src: string, dst: string) {
  return throwsError(
    (pError, src, dst) => {
      return shared().moveItemAtPath_toPath_error_(src, dst, pError);
    },
    src,
    dst,
  );
}

export function attrs(path: string) {
  const foundation = Process.getModuleByName("Foundation");

  const NS_FILE_ATTR_KEYS = {
    NSFileCreationDate: ["created", new Date()],
    NSFileGroupOwnerAccountID: ["gid", 0],
    NSFileGroupOwnerAccountName: ["group", ""],
    NSFileOwnerAccountID: ["uid", 0],
    NSFileOwnerAccountName: ["owner", ""],
    NSFilePosixPermissions: ["perm", 0],
    NSFileProtectionKey: ["protection", ""],
    NSFileSize: ["size", 0],
    NSFileType: ["type", ""],
  } as const;

  type NsFileAttrs = typeof NS_FILE_ATTR_KEYS;
  type MetaDataShape = {
    -readonly [K in keyof NsFileAttrs as NsFileAttrs[K][0]]: NsFileAttrs[K][1] extends number
      ? number
      : NsFileAttrs[K][1] extends string
        ? string
        : NsFileAttrs[K][1];
  };

  interface FileAttributes extends MetaDataShape {}

  const attrs = throwsError(
    (pError, path) => shared().attributesOfItemAtPath_error_(path, pError),
    path,
  );

  const result: Partial<FileAttributes> = {};
  for (const [nsKey, [jsKey, placeholder]] of Object.entries(
    NS_FILE_ATTR_KEYS,
  ) as [keyof NsFileAttrs, NsFileAttrs[keyof NsFileAttrs]][]) {
    const k = new ObjC.Object(
      foundation.getExportByName(nsKey).readPointer(),
    ) as NSString;
    const value = attrs.objectForKey_(k);
    result[jsKey] = valueOf(value);
  }

  return result as FileAttributes;
}

export function plist(path: string) {
  return valueOf(ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path));
}

const NSUTF8StringEncoding = 4;

export function text(path: string) {
  return ObjC.classes.NSString.stringWithContentsOfFile_encoding_error_(
    path,
    NSUTF8StringEncoding,
    NULL,
  ).toString() as string;
}

export function saveText(path: string, text: string) {
  return ObjC.classes.NSString.stringWithString_(
    text,
  ).writeToFile_atomically_encoding_error_(
    path,
    true,
    NSUTF8StringEncoding,
    NULL,
  ) as boolean;
}
