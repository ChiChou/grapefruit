import type ObjC from "frida-objc-bridge";

export interface NSObject extends ObjC.Object {
  respondsToSelector_(sel: NativePointer): boolean;
  isKindOfClass_(cls: ObjC.Object): boolean;
  toString(): string;
}

export interface NSNumber extends NSObject {
  intValue(): number;
}

export type _Nullable<T> = T | null;
export type StringLike = string | NSString;

export interface NSString extends NSObject {
  UTF8String(): NativePointer;
  writeToFile_atomically_encoding_error_(
    path: StringLike,
    atomically: boolean,
    encoding: number,
    error: NativePointer,
  ): boolean;
  lastPathComponent(): NSString;
  stringByDeletingLastPathComponent(): NSString;
  stringByDeletingPathExtension(): NSString;
  stringByAppendingPathComponent_(str: StringLike): NSString;
}

export interface NSArray<T> extends NSObject {
  count(): number;
  objectAtIndex_(index: number): T;
}

export interface NSSet<T> extends NSObject {
  count(): number;
  allObjects(): NSArray<T>;
}

export interface NSURL extends NSObject {
  absoluteString(): string;
}

export interface NSDictionary<K, V> extends NSObject {
  objectForKey_(key: K): _Nullable<V>;
  allKeys(): NSArray<K>;
  mutableCopy(): NSMutableDictionary<K, V>;
  copy(): NSDictionary<K, V>;
}

export interface NSMutableDictionary<K, V> extends NSDictionary<K, V> {
  setObject_forKey_(obj: V | string | number, key: K | string): void;
  removeObjectForKey_(key: K | string): void;
}

export interface NSDate extends NSObject {
  timeIntervalSince1970(): number;
}

export interface NSError extends NSObject {}

export interface NSData extends NSObject {}

export type NSFileAttribute = NSDictionary<NSString, NSObject>;

export interface NSFileManager extends NSObject {
  contentsOfDirectoryAtPath_error_(
    path: StringLike,
    pError: NativePointer,
  ): NSArray<NSString>;
  fileExistsAtPath_isDirectory_(
    path: StringLike,
    pIsDir: NativePointer,
  ): boolean;
  attributesOfItemAtPath_error_(
    path: StringLike,
    pError: NativePointer,
  ): NSFileAttribute;
  removeItemAtPath_error_(path: StringLike, pError: NativePointer): boolean;
  moveItemAtPath_toPath_error_(
    src: StringLike,
    dst: StringLike,
    pError: NativePointer,
  ): boolean;
  copyItemAtPath_toPath_error_(
    src: StringLike,
    dst: StringLike,
    pError: NativePointer,
  ): boolean;
  createDirectoryAtPath_withIntermediateDirectories_attributes_error_(
    path: StringLike,
    intermediate: boolean,
    attributes: _Nullable<NSFileAttribute>,
    pError: NativePointer,
  ): boolean;
  contentsOfDirectoryAtURL_includingPropertiesForKeys_options_error_(
    url: NSURL,
    keys: NSArray<NSString>,
    options: number,
    pError: NativePointer,
  ): NSArray<NSURL>;
}
