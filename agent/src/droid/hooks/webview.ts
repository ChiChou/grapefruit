import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook, bt } from "@/common/hooks/java.js";

const hooks: InvocationListener[] = [];
let running = false;

function hookWebSettings() {
  const WebSettings = Java.use("android.webkit.WebSettings");

  // setJavaScriptEnabled(boolean)
  hooks.push(
    hook(
      WebSettings.setJavaScriptEnabled.overload("boolean"),
      (original, self, args) => {
        const [value] = args as [boolean];
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebSettings.setJavaScriptEnabled",
          dir: "enter",
          line: `setJavaScriptEnabled(${value})${value ? " JS enabled" : ""}`,
          backtrace: bt(),
          extra: { setting: "javaScriptEnabled", value, risk: value ? "high" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // setAllowFileAccess(boolean)
  hooks.push(
    hook(
      WebSettings.setAllowFileAccess.overload("boolean"),
      (original, self, args) => {
        const [value] = args as [boolean];
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebSettings.setAllowFileAccess",
          dir: "enter",
          line: `setAllowFileAccess(${value})${value ? " file access enabled" : ""}`,
          backtrace: bt(),
          extra: { setting: "allowFileAccess", value, risk: value ? "medium" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // setAllowContentAccess(boolean)
  hooks.push(
    hook(
      WebSettings.setAllowContentAccess.overload("boolean"),
      (original, self, args) => {
        const [value] = args as [boolean];
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebSettings.setAllowContentAccess",
          dir: "enter",
          line: `setAllowContentAccess(${value})${value ? " content access enabled" : ""}`,
          backtrace: bt(),
          extra: { setting: "allowContentAccess", value, risk: value ? "medium" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // setAllowFileAccessFromFileURLs(boolean)
  hooks.push(
    hook(
      WebSettings.setAllowFileAccessFromFileURLs.overload("boolean"),
      (original, self, args) => {
        const [value] = args as [boolean];
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebSettings.setAllowFileAccessFromFileURLs",
          dir: "enter",
          line: `setAllowFileAccessFromFileURLs(${value})${value ? " cross-origin file access" : ""}`,
          backtrace: bt(),
          extra: { setting: "allowFileAccessFromFileURLs", value, risk: value ? "high" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // setAllowUniversalAccessFromFileURLs(boolean)
  hooks.push(
    hook(
      WebSettings.setAllowUniversalAccessFromFileURLs.overload("boolean"),
      (original, self, args) => {
        const [value] = args as [boolean];
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebSettings.setAllowUniversalAccessFromFileURLs",
          dir: "enter",
          line: `setAllowUniversalAccessFromFileURLs(${value})${value ? " universal cross-origin access" : ""}`,
          backtrace: bt(),
          extra: { setting: "allowUniversalAccessFromFileURLs", value, risk: value ? "high" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // setMixedContentMode(int)
  hooks.push(
    hook(
      WebSettings.setMixedContentMode.overload("int"),
      (original, self, args) => {
        const [mode] = args as [number];
        const MODES: Record<number, string> = {
          0: "MIXED_CONTENT_ALWAYS_ALLOW",
          1: "MIXED_CONTENT_NEVER_ALLOW",
          2: "MIXED_CONTENT_COMPATIBILITY_MODE",
        };
        const modeName = MODES[mode] || `unknown(${mode})`;
        const risky = mode === 0;
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebSettings.setMixedContentMode",
          dir: "enter",
          line: `setMixedContentMode(${modeName})${risky ? " allows HTTP in HTTPS" : ""}`,
          backtrace: bt(),
          extra: { setting: "mixedContentMode", value: modeName, risk: risky ? "high" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );
}

function hookJavascriptInterface() {
  const WebView = Java.use("android.webkit.WebView");

  // addJavascriptInterface(Object, String)
  hooks.push(
    hook(
      WebView.addJavascriptInterface.overload("java.lang.Object", "java.lang.String"),
      (original, self, args) => {
        const [, name] = args as [Java.Wrapper, Java.Wrapper];
        const ifaceName = name?.toString() || "unknown";
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebView.addJavascriptInterface",
          dir: "enter",
          line: `addJavascriptInterface(obj, "${ifaceName}") RCE risk on older APIs`,
          backtrace: bt(),
          extra: { setting: "addJavascriptInterface", value: ifaceName, interfaceName: ifaceName, risk: "high" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );
}

function hookWebViewLoads() {
  const WebView = Java.use("android.webkit.WebView");

  // loadUrl(String)
  hooks.push(
    hook(
      WebView.loadUrl.overload("java.lang.String"),
      (original, self, args) => {
        const [url] = args as [Java.Wrapper];
        const urlStr = url?.toString() || "unknown";
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebView.loadUrl",
          dir: "enter",
          line: `loadUrl("${urlStr}")`,
          backtrace: bt(),
          extra: { url: urlStr, risk: urlStr.startsWith("file://") ? "medium" : "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // loadUrl(String, Map) - with additional headers
  try {
    hooks.push(
      hook(
        WebView.loadUrl.overload("java.lang.String", "java.util.Map"),
        (original, self, args) => {
          const [url] = args as [Java.Wrapper, Java.Wrapper];
          const urlStr = url?.toString() || "unknown";
          send({
            subject: "hook",
            category: "webview",
            symbol: "WebView.loadUrl",
            dir: "enter",
            line: `loadUrl("${urlStr}", headers)`,
            backtrace: bt(),
            extra: { url: urlStr, risk: urlStr.startsWith("file://") ? "medium" : "low" },
          } satisfies BaseMessage);
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    // overload may not exist
  }

  // loadData(String, String, String)
  hooks.push(
    hook(
      WebView.loadData.overload("java.lang.String", "java.lang.String", "java.lang.String"),
      (original, self, args) => {
        const [, mimeType] = args as [Java.Wrapper, Java.Wrapper, Java.Wrapper];
        const mime = mimeType?.toString() || "unknown";
        send({
          subject: "hook",
          category: "webview",
          symbol: "WebView.loadData",
          dir: "enter",
          line: `loadData(data, "${mime}", ...)`,
          backtrace: bt(),
          extra: { risk: "low" },
        } satisfies BaseMessage);
        return original.call(self, ...args);
      },
    ),
  );

  // loadDataWithBaseURL(String, String, String, String, String)
  try {
    hooks.push(
      hook(
        WebView.loadDataWithBaseURL.overload(
          "java.lang.String",
          "java.lang.String",
          "java.lang.String",
          "java.lang.String",
          "java.lang.String",
        ),
        (original, self, args) => {
          const [baseUrl, , mimeType] = args as [Java.Wrapper, Java.Wrapper, Java.Wrapper, Java.Wrapper, Java.Wrapper];
          const base = baseUrl?.toString() || "null";
          const mime = mimeType?.toString() || "unknown";
          send({
            subject: "hook",
            category: "webview",
            symbol: "WebView.loadDataWithBaseURL",
            dir: "enter",
            line: `loadDataWithBaseURL("${base}", data, "${mime}", ...)`,
            backtrace: bt(),
            extra: { url: base, risk: base.startsWith("file://") ? "medium" : "low" },
          } satisfies BaseMessage);
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    // overload may not exist
  }
}

export function start() {
  if (running || !available()) return;
  running = true;
  Java.perform(() => {
    try {
      hookWebSettings();
    } catch (e) {
      console.warn("webview: WebSettings hooks unavailable:", e);
    }
    try {
      hookJavascriptInterface();
    } catch (e) {
      console.warn("webview: addJavascriptInterface hook unavailable:", e);
    }
    try {
      hookWebViewLoads();
    } catch (e) {
      console.warn("webview: WebView load hooks unavailable:", e);
    }
  });
}

export function stop() {
  for (const h of hooks) {
    try {
      h.detach();
    } catch {
      /* ignore */
    }
  }
  hooks.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  if (!Java.available) return false;
  let found = false;
  Java.perform(() => {
    try {
      Java.use("android.webkit.WebSettings");
      found = true;
    } catch {
      found = false;
    }
  });
  return found;
}
