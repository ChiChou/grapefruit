import { expose } from '../registry.js'

export function open(urlStr: string) {
  const app = ObjC.classes.UIApplication.sharedApplication()

  // iOS 13 UISceneDelegate
  if (ObjC.classes.UIScene) {
    const scenes = app.connectedScenes().allObjects()
    for (let i = 0; i < scenes.count(); i++) {
      const scene = scenes.objectAtIndex_(i)
      const delegate = scene.delegate()
      if (!delegate) continue
      ObjC.schedule(ObjC.mainQueue, () => {
        // prevent UAF!!
        const url = ObjC.classes.NSURL.URLWithString_(urlStr)
        const opt = ObjC.classes.UISceneOpenURLOptions.new()
        const ctx = ObjC.classes.UIOpenURLContext.new().initWithURL_options_(url, opt)
        const imp = scene.delegate().scene_openURLContexts_.implementation
        scene.delegate().scene_openURLContexts_(scene, ObjC.classes.NSSet.setWithObject_(ctx))
        console.log('request sent to url handler:', delegate, 'scene:openURLContexts:', '@' + imp)
      })
      return
    }
  }

  const candidates = [
    'application:handleOpenURL:', // iOS 2.0-9.0
    'application:openURL:sourceApplication:annotation:', // iOS 4.2–9.0
    'application:openURL:options:' // 9.0+
  ]

  const delegate = app.delegate()

  for (let sel of candidates) {
    const method = delegate[sel]
    if (typeof method === 'function') {
      ObjC.schedule(ObjC.mainQueue, () => {
        const rest = [...new Array(method.length - 2)].map(e => NULL)
        const url = ObjC.classes.NSURL.URLWithString_(urlStr)
        delegate[sel](app, url, ...rest)
        console.log('request sent to url handler:', delegate, sel, '@' + method.implementation)
      })
      return
    }
  }

  throw Error(`delegate not found. Please file a bug (bundle id: ${ObjC.classes.NSBundle.mainBundle()})`)
}

expose('url', { open })
