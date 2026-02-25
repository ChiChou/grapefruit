import ObjC from "frida-objc-bridge";
import type {
  NSObject,
  StringLike,
  NSURL,
  NSString,
} from "@/fruity/typings.js";

import { performOnMainThread } from "@/fruity/lib/dispatch.js";
import { tracker } from "@/fruity/lib/weak.js";

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
}

export type UIWebViewInfo = WebViewInfo;

function choose(clazz: ObjC.Object): Promise<ObjC.Object[]> {
  return new Promise((resolve) => {
    const instances: ObjC.Object[] = [];
    ObjC.choose(clazz, {
      onMatch(instance) {
        instances.push(instance);
      },
      onComplete() {
        resolve(instances);
      },
    });
  });
}


export async function listWK(): Promise<WKWebViewInfo[]> {
  const { WKWebView } = ObjC.classes;
  if (!WKWebView) return [];

  const kind = "WK";
  const instances = await choose(WKWebView);

  return Promise.all(
    instances.map((instance) => {
      const webview = instance as WKWebView;
      const handle = instance.handle.toString();
      tracker.put(handle, instance);

      const conf = webview.configuration() as WKWebViewConfiguration;
      const pref = conf.preferences();
      const webpagePref = conf.defaultWebpagePreferences();

      return performOnMainThread(async () => {
        const url = webview.URL()?.toString() ?? "";
        const title = await WKGetTitle(webview);

        return {
          handle,
          kind,
          url,
          title,
          js: pref.javaScriptEnabled(),
          contentJs: webpagePref.allowsContentJavaScript(),
          jsAutoOpenWindow: pref.javaScriptCanOpenWindowsAutomatically(),
        } as WKWebViewInfo;
      });
    }),
  );
}

export async function listUI(): Promise<UIWebViewInfo[]> {
  const { UIWebView } = ObjC.classes;
  if (!UIWebView) return [];

  const kind = "UI";
  const instances = await choose(UIWebView);

  return Promise.all(
    instances.map((instance) => {
      const webview = instance as UIWebView;
      const handle = instance.handle.toString();
      tracker.put(handle, instance);

      return performOnMainThread(() => {
        const req = webview.request();
        const url = req?.mainDocumentURL()?.toString() ?? "";
        const title = UIGetTitle(webview);

        return {
          handle,
          kind,
          url,
          title,
        } as UIWebViewInfo;
      });
    }),
  );
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
  return tracker.get(handle) as WebView;
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
