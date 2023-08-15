export interface NSObject extends ObjC.Object {
  respondsToSelector_(sel: NativePointer): boolean;
  isKindOfClass_(cls: ObjC.Object): boolean;
  toString(): string;
}

export interface NSNumer extends NSObject {
  intValue(): number;
}

export interface NSString extends NSObject {
  UTF8String(): NativePointer;
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
