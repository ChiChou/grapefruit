import ObjC from "frida-objc-bridge";

export class RefTracker {
  private table = ObjC.classes.NSMapTable.strongToWeakObjectsMapTable();

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
}

export const tracker = new RefTracker();
