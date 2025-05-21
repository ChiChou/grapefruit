import ObjC from 'frida-objc-bridge'
import { performOnMainThread } from "../lib/dispatch.js"
import { get as getInstance } from '../lib/choose.js'

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
      return await getInstance(clazz, handle)
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
    return performOnMainThread(() => webview.stringByEvaluatingJavaScriptFromString_(js) + '')

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

export async function dump(handle: string) {
  const webview = await get(handle)
  if (!webview.isKindOfClass_(ObjC.classes.UIWebView))
    throw new Error(`invalid UIWebView ${webview}`)

  return new Promise((resolve) => {
    performOnMainThread(() => {
      const jsc = webview.valueForKeyPath_('documentView.webView.mainFrame.javaScriptContext')
      const window = webview.windowScriptObject()
      const keys = window.evaluateWebScript_('Object.keys(this)')
      const count = keys.valueForKey_('length')
      const result: {[key: string]: string} = {}
      for (let i = 0; i < count; i++) {
        const key = keys.webScriptValueAtIndex_(i).toString()
        if (!jsc.objectForKeyedSubscript_(key).isObject()) continue
        const obj = window.valueForKey_(key)
        if (!obj.isKindOfClass_(ObjC.classes.WebScriptObject))
          result[key] = `<${obj.$className} ${obj.handle}>`
      }
      resolve(result)
    })
  })
}

export async function prefs(handle: string) {
  const webview = await get(handle)
  if (!webview.isKindOfClass_(ObjC.classes.WKWebView)) throw new Error(`${webview} is not a WKWebView`)

  const conf = webview.configuration()
  const pref = conf.preferences()

  const result = {
    customUserAgent: webview.customUserAgent().toString(),
    javaScriptEnabled: pref.javaScriptEnabled(),
    allowsContentJavaScript: undefined,
    jsAutoOpenWindow: pref.javaScriptCanOpenWindowsAutomatically(),
  }

  // > iOS 13
  if (typeof conf.defaultWebpagePreferences === 'function') {
    // todo: get preference per natigation
    result['allowsContentJavaScript'] = conf.defaultWebpagePreferences().allowsContentJavaScript()
  }

  return result
}
