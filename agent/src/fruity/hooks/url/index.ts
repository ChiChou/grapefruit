import ObjC from "frida-objc-bridge";

import { hooks } from "./common.js";
import {
  hookResume,
  hookSessionCreation,
  scanExistingSessions,
  hookAsyncMethods as hookSessionAsyncMethods,
} from "./session.js";
import {
  hookConnectionCreation,
  hookAsyncMethods as hookConnectionAsyncMethods,
} from "./connection.js";
import { hookWebSocketMethods } from "./websocket.js";
import { reset as resetLazyState } from "./lazy.js";

let running = false;

export function start() {
  if (running || !ObjC.available) return;

  console.log("start logging http URL requests");
  running = true;

  const { __NSCFURLSessionTask, NSURLSessionTask } = ObjC.classes;
  if (__NSCFURLSessionTask) {
    hooks.push(hookResume(__NSCFURLSessionTask));
  }

  if (NSURLSessionTask) {
    hooks.push(hookResume(NSURLSessionTask));
  }

  hookSessionAsyncMethods();
  hookConnectionAsyncMethods();
  hookWebSocketMethods();
  hookSessionCreation();
  hookConnectionCreation();
  scanExistingSessions();
}

export function stop() {
  if (!running) return;
  running = false;
  for (const hook of hooks) {
    hook.detach();
  }
  hooks.length = 0;
  resetLazyState();
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  return ObjC.available;
}
