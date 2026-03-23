import Java from "frida-java-bridge";
import { perform } from "@/common/hooks/java.js";
import { getTracker } from "@/droid/lib/weak.js";

export interface AndroidWebViewInfo {
  handle: string;
  url: string;
  title: string;
  settings: {
    jsEnabled: boolean;
    allowFileAccess: boolean;
    allowContentAccess: boolean;
    allowFileAccessFromFileURLs: boolean;
    allowUniversalAccessFromFileURLs: boolean;
    safeBrowsingEnabled: boolean;
    mixedContentMode: number;
    databaseEnabled: boolean;
    domStorageEnabled: boolean;
  };
  interfaces: string[];
}

function hashcode(instance: Java.Wrapper): string {
  return String(Java.use("java.lang.System").identityHashCode(instance));
}

function runOnMainThread<T>(fn: () => T): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    Java.scheduleOnMainThread(() => {
      try {
        resolve(fn());
      } catch (e) {
        reject(e);
      }
    });
  });
}

function extractInterfaces(webview: Java.Wrapper): string[] {
  const interfaces: string[] = [];
  try {
    const provider = webview.mProvider.value;
    if (provider) {
      const awContents = provider.mAwContents.value;
      if (awContents) {
        const javascriptInterfaces = awContents.mJavascriptInterfaces.value;
        if (javascriptInterfaces) {
          const iterator = javascriptInterfaces.keySet().iterator();
          while (iterator.hasNext()) {
            interfaces.push(iterator.next().toString());
          }
        }
      }
    }
  } catch {
    // Ignore reflection errors — internal fields vary across OEMs
  }
  return interfaces;
}

export function list(): Promise<AndroidWebViewInfo[]> {
  return perform(() => {
    const handles: { handle: string; instance: Java.Wrapper }[] = [];
    Java.choose("android.webkit.WebView", {
      onMatch(instance) {
        const handle = hashcode(instance);
        getTracker().put(handle, instance);
        handles.push({ handle, instance });
      },
      onComplete() {},
    });
    return handles;
  }).then((handles) => {
    if (handles.length === 0) return [];

    return runOnMainThread(() => {
      const WebView = Java.use("android.webkit.WebView");
      return handles.map(({ handle, instance }) => {
        const webview = Java.cast(instance, WebView);
        const settings = webview.getSettings();
        return {
          handle,
          url: webview.getUrl()?.toString() || "",
          title: webview.getTitle()?.toString() || "",
          settings: {
            jsEnabled: settings.getJavaScriptEnabled(),
            allowFileAccess: settings.getAllowFileAccess(),
            allowContentAccess: settings.getAllowContentAccess(),
            allowFileAccessFromFileURLs:
              settings.getAllowFileAccessFromFileURLs(),
            allowUniversalAccessFromFileURLs:
              settings.getAllowUniversalAccessFromFileURLs(),
            safeBrowsingEnabled: settings.getSafeBrowsingEnabled(),
            mixedContentMode: settings.getMixedContentMode(),
            databaseEnabled: settings.getDatabaseEnabled(),
            domStorageEnabled: settings.getDomStorageEnabled(),
          },
          interfaces: extractInterfaces(webview),
        };
      });
    });
  });
}

export function setDebugging(handle: string, enabled: boolean) {
  return runOnMainThread(() => {
    const instance = getTracker().get(handle);
    const webview = Java.cast(instance, Java.use("android.webkit.WebView"));
    webview.setWebContentsDebuggingEnabled(enabled);
  });
}

export function evaluate(handle: string, js: string): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    Java.scheduleOnMainThread(() => {
      try {
        const instance = getTracker().get(handle);
        const webview = Java.cast(
          instance,
          Java.use("android.webkit.WebView"),
        );

        const ValueCallback = Java.use("android.webkit.ValueCallback");
        const callback = Java.registerClass({
          name: `com.igf.webview.EvalCb_${Date.now()}_${Math.floor(Math.random() * 10000)}`,
          implements: [ValueCallback],
          methods: {
            onReceiveValue(value: Java.Wrapper) {
              resolve(value ? value.toString() : "");
            },
          },
        });

        webview.evaluateJavascript(js, callback.$new());
      } catch (e) {
        reject(e);
      }
    });
  });
}

export function navigate(handle: string, url: string): Promise<void> {
  return runOnMainThread(() => {
    const instance = getTracker().get(handle);
    const webview = Java.cast(instance, Java.use("android.webkit.WebView"));
    webview.loadUrl(url);
  });
}
