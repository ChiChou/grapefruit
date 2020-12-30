import { performOnMainThread } from "../lib/dispatch"

export function list() {
  const { UIWebView, WKWebView } = ObjC.classes

  return {
    ui: ObjC.chooseSync(UIWebView).map(e => e.handle),
    wk: ObjC.chooseSync(WKWebView).map(e => e.handle)
  }
}

async function get(handle: string): Promise<ObjC.Object> {
  for (const kind of ['UI', 'WK']) {
    const clazz = ObjC.classes[`${kind}WebView`]
    try {
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
            }
            reject()
          }
        })
      })
      return new ObjC.Object(webview)
    } catch (_) {

    }
  }

  throw new Error(`Unable to find WebView for handle ${handle}`)
}

export async function watch(handle: string) {
  const webview = await get(handle)
  Interceptor.attach(webview.dealloc.implementation, {
    onLeave() {
      send({
        event: 'dealloc',
        handle
      })
    }
  })

  return true
}

export async function evaluate(handle: string, js: string): Promise<string> {
  const webview = await get(handle)

  if (webview.isKindOfClass_(ObjC.classes.UIWebView)) {
    return performOnMainThread(() => webview.stringByEvaluatingJavaScriptFromString_(js))
  } else if (webview.isKindOfClass_(ObjC.classes.WKWebView)) {
    return new Promise((resolve, reject) => {
      performOnMainThread(() => webview.evaluateJavaScript_completionHandler_(js, new ObjC.Block({
        retType: 'void',
        argTypes: ['object', 'object'],
        implementation(result: ObjC.Object, error: ObjC.Object) {
          if (error)
            reject(new Error(`Unable to execute Javascript. ${error}`))
          else
            resolve('' + result)
        }
      })))
    })
  }

  throw new Error(`Unsupported class type ${webview.$className} (${handle})`)
}