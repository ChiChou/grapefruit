import { performOnMainThread } from "../lib/dispatch"

const WebViewKinds = ['UI', 'WK'] as const

type Kind = typeof WebViewKinds[number]
type WebViewsCollection = Record<Kind, { [handle: string]: string }>

export async function list(): Promise<WebViewsCollection> {
  const result: WebViewsCollection = { WK: {}, UI: {} }
  for (const kind of WebViewKinds) {
    const clazz = ObjC.classes[`${kind}WebView`]

    for (const instance of ObjC.chooseSync(clazz)) {
      const title = await evaluate(instance, 'document.title')
      const handle = instance.handle.toString()
      result[kind][handle] = title
    }
  }

  return result
}

async function get(handle: string): Promise<ObjC.Object> {
  for (const kind of WebViewKinds) {
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

export async function run(handle: string, js: string): Promise<string> {
  const webview = await get(handle)
  return evaluate(webview, js)
}

async function evaluate(webview: ObjC.Object, js: string): Promise<string> {
  if (webview.isKindOfClass_(ObjC.classes.UIWebView))
    return performOnMainThread(() => webview.stringByEvaluatingJavaScriptFromString_(js))

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

export async function url(handle: string) {
  const webview = await get(handle)
  if (webview.isKindOfClass_(ObjC.classes.UIWebView))
    return webview.request().mainDocumentURL() + ''
  return webview.URL() + ''
}

export async function navigate(handle: string, url: string) {
  const webview = await get(handle)
  return performOnMainThread(() => {
    // WARNING: performOnMainThread could lead to use after free
    const u = ObjC.classes.NSURL.URLWithString_(url)
    const req = ObjC.classes.NSURLRequest.requestWithURL_(u)
    webview.loadRequest_(req)
  })
}
