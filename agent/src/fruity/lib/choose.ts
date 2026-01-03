import ObjC from "frida-objc-bridge";

export async function get<T extends ObjC.Object>(
  clazz: T,
  handle: string,
): Promise<T> {
  const h: NativePointer = await new Promise((resolve, reject) => {
    let p: NativePointer = NULL;
    ObjC.choose(clazz, {
      onMatch(item: ObjC.Object) {
        if (item.handle.equals(handle)) {
          p = item.handle;
          return "stop";
        }
      },
      onComplete() {
        if (!p.isNull()) {
          resolve(p);
          return;
        }
        reject();
      },
    });
  });
  return new ObjC.Object(h) as T;
}
