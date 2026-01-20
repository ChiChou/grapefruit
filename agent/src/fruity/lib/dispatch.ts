import ObjC from "frida-objc-bridge";

const blocks = new Set();

export function performOnMainThread<T>(action: () => T): Promise<T> {
  const { NSThread } = ObjC.classes;

  return new Promise((resolve, reject) => {
    function performAction() {
      const application = ObjC.classes.UIApplication.sharedApplication();
      if (application === null) {
        reject(new Error("App not ready"));
        return;
      }

      const block = new ObjC.Block({
        retType: "void",
        argTypes: [],
        implementation() {
          try {
            const result = action();
            resolve(result);
          } catch (e) {
            reject(e);
          }
          setTimeout(() => blocks.delete(block), 0);
        },
      });
      blocks.add(block);

      application["- _performBlockAfterCATransactionCommits:"](block);
    }

    if (NSThread.isMainThread()) {
      performAction();
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction);
    }
  });
}
