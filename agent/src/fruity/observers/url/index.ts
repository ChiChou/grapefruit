import { ObjC, hooks } from "./common.js";
import {
  hookResume,
  hookDelegateMethods,
  hookAsyncMethods as hookSessionAsyncMethods,
  hookRespondsToSelector,
} from "./session.js";
import {
  hookDelegateMethods as hookConnectionDelegateMethods,
  hookAsyncMethods as hookConnectionAsyncMethods,
} from "./connection.js";
import { hookWebSocketMethods } from "./websocket.js";

export function start() {
  if (!ObjC.available) return;

  console.log("start logging http URL requests");

  const { __NSCFURLSessionTask, NSURLSessionTask } = ObjC.classes;
  if (__NSCFURLSessionTask) {
    hooks.push(hookResume(__NSCFURLSessionTask));
  }

  if (NSURLSessionTask) {
    hooks.push(hookResume(NSURLSessionTask));
  }

  hookSessionAsyncMethods();
  hookDelegateMethods();
  hookConnectionDelegateMethods();
  hookConnectionAsyncMethods();
  hookWebSocketMethods();
  hookRespondsToSelector();
}

export function stop() {
  for (const hook of hooks) {
    hook.detach();
  }
  hooks.length = 0;
}
