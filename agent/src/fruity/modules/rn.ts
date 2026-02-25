import ObjC from "frida-objc-bridge";
import {
  type RNArch,
  type RNInstance,
  sendHermesByteCode,
  createCallbackContext,
} from "@/common/hermes.js";
import { unlink } from "@/lib/posix.js";
import { NSData, NSURL } from "../typings.js";
import { tracker } from "@/fruity/lib/weak.js";

const CLASS_NAMES: Record<RNArch, string> = {
  legacy: "RCTCxxBridge",
  bridgeless: "RCTInstance",
};

const interceptors: InvocationListener[] = [];
const cb = createCallbackContext();
let injecting = false;


function attachBundle(
  method: ObjC.ObjectMethod | undefined,
  callbacks: InvocationListenerCallbacks,
) {
  if (!method) return;
  interceptors.push(Interceptor.attach(method.implementation, callbacks));
}

function hookBundleLoader() {
  const { RCTJavaScriptLoader } = ObjC.classes;
  if (!RCTJavaScriptLoader) return;

  attachBundle(
    RCTJavaScriptLoader[
      "+ attemptSynchronousLoadOfBundleAtURL:sourceLength:error:"
    ],
    {
      onEnter(args) {
        if (args[2].isNull()) return;
        this.url = new ObjC.Object(args[2]).toString();
      },
      onLeave(retval) {
        if (retval.isNull() || injecting) return;
        const data = new ObjC.Object(retval) as NSData;
        const len = data.length();
        if (len)
          sendHermesByteCode(this.url, ArrayBuffer.wrap(data.bytes(), len));
      },
    },
  );
}

function hookLegacyBundleExec() {
  const { RCTCxxBridge } = ObjC.classes;
  if (!RCTCxxBridge) return;

  attachBundle(RCTCxxBridge["- executeSourceCode:withSourceURL:sync:"], {
    onEnter(args) {
      if (args[2].isNull() || args[3].isNull() || injecting) return;
      const data = new ObjC.Object(args[2]) as NSData;
      const url = new ObjC.Object(args[3]) as NSURL;
      const len = data.length();
      if (len)
        sendHermesByteCode(url.toString(), ArrayBuffer.wrap(data.bytes(), len));
    },
  });

  attachBundle(RCTCxxBridge["- executeApplicationScript:url:async:"], {
    onEnter(args) {
      if (injecting) return;
      const nsData = new ObjC.Object(args[2]);
      const url = new ObjC.Object(args[3]);
      const len = nsData.length() as number;
      if (len > 0) {
        sendHermesByteCode(
          url.toString(),
          ArrayBuffer.wrap(nsData.bytes(), len),
        );
      }
    },
  });
}

function ensureCallbackHook() {
  const { RCTAlertManager } = ObjC.classes;
  const method = RCTAlertManager["- alertWithArgs:callback:"];
  const original = method.implementation;
  method.implementation = ObjC.implement(
    method,
    function (
      handle: NativePointer,
      selector: NativePointer,
      args: NativePointer,
      callback: NativePointer,
    ) {
      const message = new ObjC.Object(args.readPointer())
        .objectForKey_("message")
        .toString();
      console.debug(`React Native alert(${message})`);
      if (cb.parseCallback(message)) return;
      return original(handle, selector, args, callback);
    },
  );
  console.log('replaced RCTAlertManager["- alertWithArgs:callback:"]');
}

export function arch() {
  return {
    legacy: CLASS_NAMES.legacy in ObjC.classes,
    bridgeless: CLASS_NAMES.bridgeless in ObjC.classes,
  };
}

export function list(): RNInstance[] {
  const results: RNInstance[] = [];
  for (const [arch, className] of Object.entries(CLASS_NAMES) as [
    RNArch,
    string,
  ][]) {
    const cls = ObjC.classes[className];
    if (!cls) continue;
    ObjC.choose(cls, {
      onMatch(instance) {
        const handle = instance.handle.toString();
        tracker.put(handle, instance);
        results.push({ className, arch, handle });
      },
      onComplete() {},
    });
  }
  return results;
}

export function inject(
  handle: string,
  arch: RNArch,
  script: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const className = CLASS_NAMES[arch];
    const cls = ObjC.classes[className];
    if (!cls) {
      reject(new Error("Class not found: " + className));
      return;
    }

    const instance = tracker.get(handle);
    const { id, path } = cb.prepare(script);
    console.log(`[rn.inject] ${arch} id=${id} path=${path}`);

    ensureCallbackHook();
    cb.register(id, (result) => {
      unlink(path);
      resolve(result);
    });

    injecting = true;
    try {
      if (arch === "legacy") {
        const nsData = ObjC.classes.NSData.dataWithContentsOfFile_(path);
        const nsURL = ObjC.classes.NSURL.fileURLWithPath_(path);
        instance["- enqueueApplicationScript:url:onComplete:"](
          nsData,
          nsURL,
          NULL,
        );
      } else {
        const sel = ["- _loadJSBundle:", "- loadJSBundle:"].find(
          (s) => s in cls,
        );
        if (!sel) {
          cb.cleanup(id, path);
          reject(new Error("No loadJSBundle method found on " + className));
          return;
        }
        instance[sel](ObjC.classes.NSURL.fileURLWithPath_(path));
      }
    } finally {
      injecting = false;
    }
  });
}

setImmediate(() => {
  hookBundleLoader();
  hookLegacyBundleExec();
});
