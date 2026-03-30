import ObjC from "frida-objc-bridge";
import type {
  NSString,
  NSFileManager,
  NSDictionary,
} from "@/fruity/typings.js";

import { toJS } from "@/fruity/bridge/object.js";
import { dump } from "@/fruity/lib/plist.js";
import * as posix from "@/lib/posix.js";
import { readdirSync, lstatSync } from "fs";
import type { Roots } from "@/common/fs.js";

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

export interface MetaData {
  name: string;
  dir: boolean;
  protection: string | null;
  size: number | null;
  alias: boolean;
  created: Date;
  symlink: boolean;
}

let cachedRoots: Roots | null = null;

export function roots(): Roots {
  if (!cachedRoots) {
    cachedRoots = {
      home: ObjC.classes.NSString.stringWithString_("~")
        .stringByExpandingTildeInPath()
        .toString() as string,
      bundle: ObjC.classes.NSBundle.mainBundle()
        .bundlePath()
        .toString() as string,
    };
  }
  return cachedRoots;
}

export interface DirectoryListing {
  cwd: string;
  writable: boolean;
  list: MetaData[];
}

// Note: we migrate from ObjC dictionaryWithContentsOfFile_ api to POSIX to
// mitigate a memory leak problem we do not have enough time to investigate.
// However, in this way we lost some metadata like NSFileProtectionType
//
// Right now we are not using the protection info, but this is useful for
// pentest purpose. Consider adding it back in the future.

export function ls(path: string): DirectoryListing {
  const names = readdirSync(path);
  const writable = posix.isWritable(path);
  const list: MetaData[] = [];

  for (const name of names) {
    if (name.startsWith(".")) continue;

    const fullPath = path + "/" + name;
    let size: number | null = null;
    let created = new Date(0);
    let protection: string | null = null;
    let isDir = false;
    let isSymlink = false;

    try {
      const stat = lstatSync(fullPath);
      isDir = stat.isDirectory();
      isSymlink = stat.isSymbolicLink();
      size = isDir ? null : stat.size.valueOf();
      created = stat.birthtime;
      protection = "0" + (stat.mode & 0o7777).toString(8);
    } catch {
      continue;
    }

    list.push({
      name,
      dir: isDir,
      protection,
      size,
      alias: false,
      created,
      symlink: isSymlink,
    });
  }

  return { cwd: path, writable, list };
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
  return posix.rename(src, dst);
}

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
type FileAttributes = {
  -readonly [K in keyof NsFileAttrs as NsFileAttrs[K][0]]: NsFileAttrs[K][1] extends number
    ? number
    : NsFileAttrs[K][1] extends string
      ? string
      : NsFileAttrs[K][1];
};

export function attrs(path: string) {
  const foundation = Process.getModuleByName("Foundation");

  const attrs = throwsError(
    (pError, path) => shared().attributesOfItemAtPath_error_(path, pError),
    path,
  );

  const result: Record<string, unknown> = {};
  for (const [nsKey, [jsKey, placeholder]] of Object.entries(
    NS_FILE_ATTR_KEYS,
  ) as [keyof NsFileAttrs, NsFileAttrs[keyof NsFileAttrs]][]) {
    const k = new ObjC.Object(
      foundation.getExportByName(nsKey).readPointer(),
    ) as NSString;
    const value = attrs.objectForKey_(k);
    result[jsKey] = toJS(value);
  }

  return result as FileAttributes;
}

export function plist(path: string) {
  return dump(ObjC.classes.NSDictionary.dictionaryWithContentsOfFile_(path));
}

const NSUTF8StringEncoding = 4;

export function text(path: string) {
  const result = throwsError(
    (pError, path) =>
      ObjC.classes.NSString.stringWithContentsOfFile_encoding_error_(
        path,
        NSUTF8StringEncoding,
        pError,
      ),
    path,
  );
  if (!result) throw new Error(`Cannot read file: ${path}`);
  return result.toString() as string;
}

export function data(path: string) {
  const nsdata = ObjC.classes.NSData.dataWithContentsOfFile_(path);
  if (!nsdata) return null;
  const len = nsdata.length() as number;
  if (len === 0) return new ArrayBuffer(0);
  return nsdata.bytes().readByteArray(len);
}

const PREVIEW_LIMIT = 1024 * 1024;

export function preview(path: string) {
  const handle = ObjC.classes.NSFileHandle.fileHandleForReadingAtPath_(path);
  if (!handle) return null;
  try {
    const size = handle.seekToEndOfFile() as number;
    if (size > PREVIEW_LIMIT)
      throw new Error(`File too large (${(size / 1024 / 1024).toFixed(1)} MB)`);
    handle.seekToFileOffset_(0);
    const nsdata = handle.readDataOfLength_(PREVIEW_LIMIT);
    const len = nsdata.length() as number;
    if (len === 0) return new ArrayBuffer(0);
    return nsdata.bytes().readByteArray(len);
  } finally {
    handle.closeFile();
  }
}

export function mkdirp(p: string) {
  return throwsError((pError, path) => {
    return shared().createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
      path,
      true,
      null,
      pError,
    );
  }, p);
}

export function access(path: string): boolean {
  return posix.isWritable(path);
}

export function saveText(path: string, text: string) {
  const nsstr = ObjC.classes.NSString.stringWithString_(text) as NSString;
  return nsstr.writeToFile_atomically_encoding_error_(
    path,
    true,
    NSUTF8StringEncoding,
    NULL,
  ) as boolean;
}
