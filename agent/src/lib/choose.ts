import ObjC from "frida-objc-bridge"

export async function get(clazz: ObjC.Object, handle: string): Promise<ObjC.Object> {
  const webview: NativePointer = await new Promise((resolve, reject) => {
    let p: NativePointer = NULL
    ObjC.choose(clazz, {
      onMatch(item) {
        if (item.handle.equals(handle)) {
          p = item.handle
          return 'stop'
        }
      },
      onComplete() {
        if (!p.isNull()) {
          resolve(p)
          return;
        }
        reject()
      }
    })
  })
  return new ObjC.Object(webview)
}
