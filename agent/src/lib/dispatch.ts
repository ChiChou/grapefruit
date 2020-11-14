export function performOnMainThread(action: Function): Promise<any> {
  const { NSThread } = ObjC.classes

  return new Promise((resolve, reject) => {
    function performAction() {
      try {
        const result = action()
        resolve(result)
      } catch (e) {
        reject(e)
      }
    }

    if (NSThread.isMainThread()) {
      performAction()
    } else {
      ObjC.schedule(ObjC.mainQueue, performAction)
    }
  })
}
