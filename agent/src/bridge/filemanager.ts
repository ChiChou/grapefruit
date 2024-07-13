import { StringLike, NSObject, NSArray, NSDictionary, _Nullable, NSString, NSURL } from "./foundation";

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

function throwsNSError(): (target: FileManager, propertyKey: string, descriptor: PropertyDescriptor) => void {
  return function (target: FileManager, propertyKey: string, descriptor: PropertyDescriptor) {
    const originalMethod = descriptor.value;
    descriptor.value = function (...args: any[]) {
      const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
      const result = originalMethod.apply(this, args.concat(pError))
      const err = pError.readPointer()
      if (!err.isNull())
        throw new Error(new ObjC.Object(err).localizedDescription())
      return result
    }
  }
}

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
  mkdir(path: StringLike, intermediate=true, attributes: _Nullable<NSFileAttribute>=null) {
    return this.manager.createDirectoryAtPath_withIntermediateDirectories_attributes_error_(path, intermediate, attributes, this.pError)
  }

  @throwsNSError()
  attr(path: StringLike) {
    return this.manager.attributesOfItemAtPath_error_(path, this.pError) as NSFileAttribute
  }

  exists(path: StringLike) {
    const isDir = Memory.alloc(Process.pointerSize).writePointer(NULL)
    const result = this.manager.fileExistsAtPath_isDirectory_(path, isDir)
    return [result, isDir.readPointer().readU8() === 1]
  }

  @throwsNSError()
  contentsOf(url: NSURL, keys: NSArray<NSString>, options: number) {
    return this.manager.contentsOfDirectoryAtURL_includingPropertiesForKeys_options_error_(url, keys, options, this.pError) as NSArray<NSURL>
  }
}

