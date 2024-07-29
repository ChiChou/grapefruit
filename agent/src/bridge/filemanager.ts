import { StringLike, NSObject, NSArray, NSDictionary, _Nullable, NSString, NSURL } from "./foundation.js";
import { valueOf } from "./dictionary.js";

type NSFileAttribute = NSDictionary<NSString, NSObject>

interface NSFileManager extends NSObject {
  contentsOfDirectoryAtPath_error_(path: StringLike, pError: NativePointer): NSArray<NSString>;
  fileExistsAtPath_isDirectory_(path: StringLike, pIsDir: NativePointer): boolean;
  attributesOfItemAtPath_error_(path: StringLike, pError: NativePointer): NSFileAttribute;
  removeItemAtPath_error_(path: StringLike, pError: NativePointer): boolean;
  moveItemAtPath_toPath_error_(src: StringLike, dst: StringLike, pError: NativePointer): boolean;
  copyItemAtPath_toPath_error_(src: StringLike, dst: StringLike, pError: NativePointer): boolean;
  createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
    path: StringLike, intermediate: boolean, attributes: _Nullable<NSFileAttribute>, pError: NativePointer): boolean;
  contentsOfDirectoryAtURL_includingPropertiesForKeys_options_error_(
    url: NSURL, keys: NSArray<NSString>, options: number, pError: NativePointer): NSArray<NSURL>;
}

function throwsNSError() {
  return function (target: FileManager, propertyKey: string, descriptor: PropertyDescriptor) {
    type F = typeof descriptor.value
    const originalMethod = descriptor.value;
    
    descriptor.value = function (...args: Parameters<F>): ReturnType<F> {
      const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
      const result = originalMethod.apply(this, args.concat(pError))
      const err = pError.readPointer()
      if (!err.isNull())
        throw new Error(new ObjC.Object(err).localizedDescription())
      return result
    }
  }
}

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

class FileManager {
  manager: NSFileManager;
  pError: NativePointer;

  constructor(manager: NSFileManager) {
    this.manager = manager
    this.pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
  }

  static get() {
    return new FileManager(ObjC.classes.NSFileManager.defaultManager() as NSFileManager)
  }

  @throwsNSError()
  ls(path: StringLike) {
    return this.manager.contentsOfDirectoryAtPath_error_(path, this.pError) as NSArray<NSString>
  }

  @throwsNSError()
  rm(path: StringLike) {
    return this.manager.removeItemAtPath_error_(path, this.pError)
  }

  @throwsNSError()
  cp(src: StringLike, dst: StringLike) {
    return this.manager.copyItemAtPath_toPath_error_(src, dst, this.pError)
  }

  @throwsNSError()
  mv(src: StringLike, dst: StringLike) {
    return this.manager.moveItemAtPath_toPath_error_(src, dst, this.pError)
  }

  @throwsNSError()
  mkdir(path: StringLike, intermediate = true, attributes: _Nullable<NSFileAttribute> = null) {
    return this.manager.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, intermediate, attributes, this.pError)
  }

  @throwsNSError()
  attr(path: StringLike) {
    const dict = this.manager.attributesOfItemAtPath_error_(path, this.pError) as NSFileAttribute
    return Object.fromEntries(
      Object.entries(NSFileAttributeKeyLookup).map(([key, value]) => ([key, valueOf(dict.objectForKey_(value))]))
    )
  }

  exists(path: StringLike) {
    const isDir = Memory.alloc(Process.pointerSize).writePointer(NULL)
    const result = this.manager.fileExistsAtPath_isDirectory_(path, isDir)
    return [result, isDir.readPointer().readU8() === 1]
  }

  @throwsNSError()
  contentsOf(url: NSURL, withHidden: boolean = false) {
    const NSDirectoryEnumerationSkipsHiddenFiles = 1 << 2
    const opt = withHidden ? 0 : NSDirectoryEnumerationSkipsHiddenFiles
    const result = this.manager.contentsOfDirectoryAtURL_includingPropertiesForKeys_options_error_(
      url, expectedKeys, opt, this.pError) as NSArray<NSURL>

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
}

const singleton = FileManager.get()
export default singleton
