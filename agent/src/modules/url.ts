export function open(urlStr: string) {
	const url = ObjC.classes.NSURL.URLWithString_(urlStr)
	const app = ObjC.classes.UIApplication.sharedApplication()

	// iOS 13 UISceneDelegate
	if (ObjC.classes.UIScene) {
    // randomly pick a scene
		const scene = app.connectedScenes().anyObject()
		if (scene) {
			const opt = ObjC.classes.UISceneOpenURLOptions.new()
			const ctx = ObjC.classes.UIOpenURLContext.new().initWithURL_options_(url, opt)
			ObjC.schedule(ObjC.mainQueue, () => {
				scene.delegate().scene_openURLContexts_(scene, ObjC.classes.NSSet.setWithObject_(ctx))
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
			const rest = [...new Array(method.length - 2)].map(e => NULL)
			console.log('url handler:', sel, method.length, ...rest)
			ObjC.schedule(ObjC.mainQueue, () => {
				delegate[sel](app, url, ...rest)
			})
			return
		}
  }

  throw Error('delegate not found. Please file a bug')
}
