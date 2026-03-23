import ObjC from "frida-objc-bridge";
import type {
  NSObject,
  StringLike,
  NSURL,
  NSString,
} from "@/fruity/typings.js";

import { performOnMainThread } from "@/fruity/lib/dispatch.js";
import { getTracker } from "@/fruity/lib/weak.js";

const WebViewKinds = ["UI", "WK"] as const;

type Kind = (typeof WebViewKinds)[number];

interface NSURLRequest extends NSObject {
  initWithURL_(url: NSURL): NSURLRequest;
}

interface WKPreferences extends NSObject {
  javaScriptCanOpenWindowsAutomatically(): boolean;
  siteSpecificQuirksModeEnabled(): boolean;
  fraudulentWebsiteWarningEnabled(): boolean;

  javaScriptEnabled(): boolean;
}

interface WKWebpagePreferences extends NSObject {
  allowsContentJavaScript(): boolean;
  lockdownModeEnabled(): boolean;
}

interface WKWebViewConfiguration extends NSObject {
  websiteDataStore(): NSObject;
  preferences(): WKPreferences;
  defaultWebpagePreferences(): WKWebpagePreferences;
}

interface WKWebView extends NSObject {
  configuration(): WKWebViewConfiguration;
  evaluateJavaScript_completionHandler_(
    js: StringLike,
    handler: ObjC.Block,
  ): void;
  URL(): NSURL;
  loadRequest_(req: NSURLRequest): void;
  isInspectable(): boolean;
  setInspectable_(value: number): void;
}

interface WebScriptObject extends NSObject {
  valueForKey_(key: StringLike): NSObject;
  evaluateWebScript_(script: StringLike): NSObject;
}

interface UIWebView extends NSObject {
  request(): NSURLRequest;
  URL(): NSURL;
  stringByEvaluatingJavaScriptFromString_(js: StringLike): NSString;
  valueForKeyPath_(key: StringLike): NSObject;
  windowScriptObject(): WebScriptObject;
  loadRequest_(req: NSURLRequest): void;
}

type WebView = UIWebView | WKWebView;

export interface WebViewInfo {
  handle: string;
  kind: Kind;
  title?: string;
  url?: string;
}

export interface WKWebViewInfo extends WebViewInfo {
  js: boolean; // javaScriptEnabled
  contentJs?: boolean; // allowsContentJavaScript
  fileURLAccess?: boolean; // allowFileAccessFromFileURLs
  universalFileAccess?: boolean; // allowUniversalAccessFromFileURLs
  secure?: boolean; // iOS 16.4+ contentBlockersEnabled
  jsAutoOpenWindow: boolean; // javaScriptCanOpenWindowsAutomatically
  inspectable?: boolean; // iOS 16.4+ isInspectable
}

export type UIWebViewInfo = WebViewInfo;

function supportsInspector() {
  return typeof ObjC.classes.WKWebView?.["- isInspectable"] === "function";
}

export function listWK(): Promise<WKWebViewInfo[]> {
  const { WKWebView } = ObjC.classes;
  if (!WKWebView) return Promise.resolve([]);

  const kind = "WK";
  const canInspect = supportsInspector();

  return performOnMainThread(async () => {
    const instances = ObjC.chooseSync({ class: WKWebView, subclasses: true });
    const results: WKWebViewInfo[] = [];

    for (const instance of instances) {
      const webview = instance as WKWebView;
      const handle = instance.handle.toString();
      getTracker().put(handle, instance);

      const conf = webview.configuration() as WKWebViewConfiguration;
      const pref = conf.preferences();
      const webpagePref = conf.defaultWebpagePreferences();

      const url = webview.URL()?.toString() ?? "";
      const title = await WKGetTitle(webview);

      const info: WKWebViewInfo = {
        handle,
        kind,
        url,
        title,
        js: pref.javaScriptEnabled(),
        contentJs: webpagePref.allowsContentJavaScript(),
        jsAutoOpenWindow: pref.javaScriptCanOpenWindowsAutomatically(),
      };

      if (canInspect) {
        info.inspectable = webview.isInspectable();
      }

      results.push(info);
    }

    return results;
  });
}

export function listUI(): Promise<UIWebViewInfo[]> {
  const { UIWebView } = ObjC.classes;
  if (!UIWebView) return Promise.resolve([]);

  const kind = "UI";

  return performOnMainThread(() => {
    const instances = ObjC.chooseSync(UIWebView);
    const results: UIWebViewInfo[] = [];

    for (const instance of instances) {
      const webview = instance as UIWebView;
      const handle = instance.handle.toString();
      getTracker().put(handle, instance);

      const req = webview.request();
      const url = req?.mainDocumentURL()?.toString() ?? "";
      const title = UIGetTitle(webview);

      results.push({ handle, kind, url, title });
    }

    return results;
  });
}

function WKGetTitle(webview: WKWebView) {
  if (!ObjC.classes.NSThread.isMainThread()) throw new Error("Invalid thread");

  return new Promise<string>((resolve, reject) =>
    webview.evaluateJavaScript_completionHandler_(
      "document.title",
      new ObjC.Block({
        retType: "void",
        argTypes: ["object", "object"],
        implementation(result: ObjC.Object, error: ObjC.Object) {
          if (error) reject(new Error(`Unable to get title. ${error}`));
          else resolve("" + result);
        },
      }),
    ),
  );
}

function UIGetTitle(webview: UIWebView) {
  if (!ObjC.classes.NSThread.isMainThread()) throw new Error("Invalid thread");

  try {
    return (
      webview.stringByEvaluatingJavaScriptFromString_("document.title") + ""
    );
  } catch (e) {
    throw new Error(`Unable to get title. ${e}`);
  }
}

function getInstance(kind: Kind, handle: string): WebView {
  return getTracker().get(handle) as WebView;
}

export async function evaluate(kind: Kind, handle: string, js: string) {
  const instance = getInstance(kind, handle);

  if (kind === "UI") {
    return performOnMainThread(() => {
      const webview = instance as UIWebView;
      return webview.stringByEvaluatingJavaScriptFromString_(js) + "";
    });
  }

  return new Promise((resolve, reject) => {
    const webview = instance as WKWebView;
    webview.evaluateJavaScript_completionHandler_(
      js,
      new ObjC.Block({
        retType: "void",
        argTypes: ["object", "object"],
        implementation(result: ObjC.Object, error: ObjC.Object) {
          if (error)
            reject(new Error(`Unable to execute Javascript. ${error}`));
          else resolve("" + result);
        },
      }),
    );
  });
}

export async function navigate(
  kind: Kind,
  handle: string,
  url: string,
): Promise<void> {
  const instance = getInstance(kind, handle);

  if (kind === "UI") {
    return performOnMainThread(() => {
      const webview = instance as UIWebView;
      const u = ObjC.classes.NSURL.URLWithString_(url);
      const req = ObjC.classes.NSURLRequest.requestWithURL_(u);
      webview.loadRequest_(req);
    });
  }

  return performOnMainThread(() => {
    const webview = instance as WKWebView;
    const u = ObjC.classes.NSURL.URLWithString_(url);
    const req = ObjC.classes.NSURLRequest.requestWithURL_(u);
    webview.loadRequest_(req);
  });
}

export async function setInspectable(
  handle: string,
  enabled: boolean,
): Promise<void> {
  const canInspect = supportsInspector();
  if (!canInspect) {
    throw new Error("setInspectable requires iOS 16.4+");
  }

  const instance = getTracker().get(handle);
  return performOnMainThread(() => {
    const webview = instance as WKWebView;
    webview.setInspectable_(enabled ? 1 : 0);
  });
}

// export async function dump(handle: string): Promise<Record<string, string>> {
//   return performOnMainThread(() => {
//     const webview = findWebViewSync(handle, "UI") as UIWebView | null;
//     if (!webview) throw new Error(`UIWebView ${handle} not found`);

//     const jsc = webview.valueForKeyPath_(
//       "documentView.webView.mainFrame.javaScriptContext",
//     );
//     const window = webview.windowScriptObject();
//     const keys = window.evaluateWebScript_("Object.keys(this)");
//     const count = (
//       keys as unknown as { valueForKey_(k: string): number }
//     ).valueForKey_("length");
//     const result: Record<string, string> = {};

//     for (let i = 0; i < count; i++) {
//       const key = (
//         keys as unknown as { webScriptValueAtIndex_(i: number): NSObject }
//       )
//         .webScriptValueAtIndex_(i)
//         .toString();
//       if (
//         !(jsc as unknown as { objectForKeyedSubscript_(k: string): NSObject })
//           .objectForKeyedSubscript_(key)
//           .isObject()
//       )
//         continue;
//       const obj = window.valueForKey_(key);
//       if (!obj.isKindOfClass_(ObjC.classes.WebScriptObject))
//         result[key] = `<${obj.$className} ${obj.handle}>`;
//     }

//     return result;
//   });
// }
