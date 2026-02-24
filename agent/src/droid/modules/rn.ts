import Java from "frida-java-bridge";
import { perform } from "@/common/hooks/java.js";
import {
  type RNArch,
  type RNInstance,
  sendHermesByteCode,
  createCallbackContext,
} from "@/common/hermes.js";
import { readFile, unlink } from "@/lib/posix.js";

const CLASS_NAMES: Record<RNArch, string> = {
  legacy: "com.facebook.react.bridge.CatalystInstanceImpl",
  bridgeless: "com.facebook.react.runtime.ReactInstance",
};

let injecting = false;
const cb = createCallbackContext();
let callbackHooked = false;

function hookBundleLoader() {
  try {
    const CatalystInstanceImpl = Java.use(CLASS_NAMES.legacy);
    CatalystInstanceImpl.loadScriptFromFile.implementation = function (
      fileName: string,
      sourceURL: string,
      loadSynchronously: boolean,
    ) {
      if (!injecting && fileName) {
        const bytes = readFile(fileName);
        if (bytes) sendHermesByteCode(fileName, bytes);
      }
      return this.loadScriptFromFile(fileName, sourceURL, loadSynchronously);
    };
  } catch {}
}

function ensureCallbackHook() {
  if (callbackHooked) return;
  callbackHooked = true;

  const DialogModule = Java.use(
    "com.facebook.react.modules.dialog.DialogModule",
  );
  DialogModule.showAlert.implementation = function (
    opt: Java.Wrapper,
    errorCallback: Java.Wrapper,
    actionCallback: Java.Wrapper,
  ) {
    const msg = opt.getString("message");
    if (msg && cb.parseCallback(msg.toString())) return;
    return this.showAlert(opt, errorCallback, actionCallback);
  };
}

function hashcode(instance: Java.Wrapper): string {
  return String(Java.use("java.lang.System").identityHashCode(instance));
}

export function arch() {
  return perform(() => {
    const result = { legacy: false, bridgeless: false };
    try { Java.use(CLASS_NAMES.legacy); result.legacy = true; } catch {}
    try { Java.use(CLASS_NAMES.bridgeless); result.bridgeless = true; } catch {}
    return result;
  });
}

export function list() {
  return perform(() => {
    const results: RNInstance[] = [];
    for (const [arch, className] of Object.entries(CLASS_NAMES) as [
      RNArch,
      string,
    ][]) {
      try {
        Java.choose(className, {
          onMatch(instance) {
            results.push({ className, arch, handle: hashcode(instance) });
          },
          onComplete() {},
        });
      } catch {}
    }
    return results;
  });
}

export function inject(
  handle: string,
  arch: RNArch,
  script: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      const className = CLASS_NAMES[arch];
      let found: Java.Wrapper | null = null;

      Java.choose(className, {
        onMatch(instance) {
          if (hashcode(instance) === handle) {
            found = instance;
            return "stop" as const;
          }
        },
        onComplete() {},
      });

      if (!found) {
        reject(new Error("Instance not found for handle: " + handle));
        return;
      }

      const instance = found as Java.Wrapper;
      const { id, path } = cb.prepare(script);

      ensureCallbackHook();
      cb.register(id, resolve);

      injecting = true;
      try {
        const url = "file://" + path;
        if (arch === "bridgeless") {
          instance.loadJSBundleFromFile(path, url);
        } else {
          instance.loadScriptFromFile(path, url, false);
        }
      } finally {
        injecting = false;
      }

      unlink(path);
    });
  });
}

perform(() => {
  hookBundleLoader();
});
