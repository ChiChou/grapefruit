import ObjC from "frida-objc-bridge";
import { StringLike } from "../typings.js";

interface NSMapTable extends ObjC.Object {
  retain(): NSMapTable;
  setObject_forKey_(object: ObjC.Object, key: StringLike): void;
  objectForKey_(key: StringLike): ObjC.Object | null;
  release(): void;
}

export class RefTracker {
  private table: NSMapTable =
    ObjC.classes.NSMapTable.strongToWeakObjectsMapTable().retain();

  put(handle: string, instance: ObjC.Object) {
    this.table.setObject_forKey_(instance, handle);
  }

  has(handle: string): boolean {
    return this.table.objectForKey_(handle) !== null;
  }

  get(handle: string) {
    const obj = this.table.objectForKey_(handle);
    if (!obj) throw new Error(`(${handle}) has been deallocated`);
    return obj as ObjC.Object;
  }

  release() {
    this.table.release();
  }
}

let singleton: RefTracker | null = null;

export function getTracker(): RefTracker {
  if (!singleton) singleton = new RefTracker();
  return singleton;
}

Script.bindWeak(globalThis, () => {
  singleton?.release();
});
