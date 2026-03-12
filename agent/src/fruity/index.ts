import ObjC from "frida-objc-bridge";

import { init as setupExceptionHandler } from "@/common/exception.js";
import { init as enableLifeCycleHook } from "./observers/lifecycle.js";
import { interfaces, invoke } from "./registry.js";
import * as pins from "./pins.js";
import type { PinRule } from "@/common/pins.js";

import "@/common/encode-arraybuffer.js";

setupExceptionHandler();
setImmediate(enableLifeCycleHook);

if (ObjC.available && ObjC.classes.UIApplication) {
  // disable autolock
  ObjC.schedule(ObjC.mainQueue, () => {
    try {
      ObjC.classes.UIApplication.sharedApplication()?.setIdleTimerDisabled_(
        ptr(1),
      );
    } finally {
    }
  });
}

rpc.exports = {
  invoke(namespace: string, method: string, args?: unknown[]) {
    const action = () => invoke(namespace, method, args || []);
    if (ObjC.available && ObjC.classes.NSAutoreleasePool) {
      const pool = ObjC.classes.NSAutoreleasePool.alloc().init();
      try {
        return action();
      } finally {
        pool.release();
      }
    } else {
      return action();
    }
  },
  interfaces,
  restore(rules: PinRule[]) {
    pins.restore(rules);
  },
  snapshot() {
    return pins.snapshot();
  },
};
