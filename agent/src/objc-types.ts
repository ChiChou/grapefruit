export interface NSObject extends ObjC.Object {
  respondsToSelector_(sel: NativePointer): boolean;
  isKindOfClass_(cls: ObjC.Object): boolean;
  toString(): string;
}

export interface NSNumber extends NSObject {
  intValue(): number;
}

export type StringLike = string | NSString;

export interface NSString extends NSObject {
  UTF8String(): NativePointer;
  writeToFile_atomically_encoding_error_(path: StringLike, atomically: boolean, encoding: number, error: NativePointer): boolean;
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
  objectForKey_(key: K): V;
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

export interface NSError extends NSObject {

}

export interface NSData extends NSObject {

}
