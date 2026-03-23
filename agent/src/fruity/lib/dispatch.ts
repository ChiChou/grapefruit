import ObjC from "frida-objc-bridge";

export function performOnMainThread<T>(action: () => T): Promise<Awaited<T>> {
  const { NSThread } = ObjC.classes;

  return new Promise((resolve, reject) => {
    async function performAction() {
      try {
        const result = await action();
        resolve(result);
      } catch (e) {
        reject(e);
      }
    }

    if (NSThread.isMainThread()) {
      performAction();
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction);
    }
  });
}
