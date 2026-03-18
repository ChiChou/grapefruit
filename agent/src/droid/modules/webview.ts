import Java from "frida-java-bridge";

import { getTracker } from "@/droid/lib/weak.js";

export interface AndroidWebViewInfo {
  handle: string;
  title?: string;
  url?: string;
  javaScriptEnabled: boolean;
  allowFileAccess: boolean;
  allowContentAccess: boolean;
  allowFileAccessFromFileURLs: boolean;
  allowUniversalAccessFromFileURLs: boolean;
  mixedContentMode: number;
  mixedContentModeName: string;
  domStorageEnabled: boolean;
  databaseEnabled: boolean;
  userAgent: string;
  jsInterfaceNames: string[];
}

const MIXED_CONTENT_MODES: Record<number, string> = {
  0: "ALWAYS_ALLOW",
  1: "NEVER_ALLOW",
  2: "COMPATIBILITY_MODE",
};

function collectInterfaces(webview: Java.Wrapper): string[] {
  // There's no public API to list JS interfaces, but we can try
  // reading the internal mJavascriptInterfaces map via reflection
  try {
    const field = webview.getClass().getDeclaredField("mJavascriptInterfaces");
    field.setAccessible(true);
    const map = Java.cast(field.get(webview), Java.use("java.util.Map"));
    const keySet = map.keySet();
    const iter = keySet.iterator();
    const names: string[] = [];
    while (iter.hasNext()) {
      names.push(iter.next().toString());
    }
    return names;
  } catch {
    return [];
  }
}

export function list(): AndroidWebViewInfo[] {
  if (!Java.available) return [];

  const results: AndroidWebViewInfo[] = [];

  Java.performNow(() => {
    const WebView = Java.use("android.webkit.WebView");

    Java.choose("android.webkit.WebView", {
      onMatch(instance) {
        try {
          const wv = Java.cast(instance, WebView);
          const handle = `${instance.$handle}`;
          getTracker().put(handle, wv);

          const settings = wv.getSettings();

          results.push({
            handle,
            title: wv.getTitle()?.toString() ?? "",
            url: wv.getUrl()?.toString() ?? "",
            javaScriptEnabled: settings.getJavaScriptEnabled(),
            allowFileAccess: settings.getAllowFileAccess(),
            allowContentAccess: settings.getAllowContentAccess(),
            allowFileAccessFromFileURLs: settings.getAllowFileAccessFromFileURLs(),
            allowUniversalAccessFromFileURLs: settings.getAllowUniversalAccessFromFileURLs(),
            mixedContentMode: settings.getMixedContentMode(),
            mixedContentModeName:
              MIXED_CONTENT_MODES[settings.getMixedContentMode()] ??
              `unknown(${settings.getMixedContentMode()})`,
            domStorageEnabled: settings.getDomStorageEnabled(),
            databaseEnabled: settings.getDatabaseEnabled(),
            userAgent: settings.getUserAgentString()?.toString() ?? "",
            jsInterfaceNames: collectInterfaces(wv),
          });
        } catch (e) {
          console.warn("webview: failed to inspect instance:", e);
        }
      },
      onComplete() {},
    });
  });

  return results;
}

export function evaluate(handle: string, js: string): Promise<string> {
  const wv = getTracker().get(handle);

  return new Promise((resolve, reject) => {
    Java.scheduleOnMainThread(() => {
      try {
        const ValueCallback = Java.use("android.webkit.ValueCallback");
        const callback = Java.registerClass({
          name: "com.igf.grape.WebViewEvalCallback" + Date.now(),
          implements: [ValueCallback],
          methods: {
            onReceiveValue(value: Java.Wrapper) {
              resolve(value === null ? "null" : value.toString());
            },
          },
        });

        wv.evaluateJavascript(js, callback.$new());
      } catch (e) {
        reject(new Error(`evaluateJavascript failed: ${e}`));
      }
    });
  });
}

export function navigate(handle: string, url: string): void {
  const wv = getTracker().get(handle);
  Java.scheduleOnMainThread(() => {
    wv.loadUrl(url);
  });
}
