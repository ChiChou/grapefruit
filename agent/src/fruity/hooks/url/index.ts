/*

This module follows the approach of PonyDebugger to log NSURLSession traffics
https://github.com/FLEXTool/FLEX/blob/6cfc82bd9e64832/Classes/Network/PonyDebugger/

PonyDebugger
Copyright 2012 Square Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

import ObjC from "frida-objc-bridge";

import { hooks } from "./common.js";
import {
  hookResume,
  hookTaskCompletion,
  hookSessionCreation,
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

  const { __NSCFURLSessionTask, NSURLSessionTask, __NSCFLocalSessionTask } =
    ObjC.classes;

  // https://github.com/FLEXTool/FLEX/blob/6cfc82bd9e6483/Classes/Network/PonyDebugger/FLEXNetworkObserver.m#L607
  // In iOS 7 resume lives in __NSCFLocalSessionTask
  // In iOS 8 resume lives in NSURLSessionTask
  // In iOS 9 resume lives in __NSCFURLSessionTask
  // In iOS 14 resume lives in NSURLSessionTask

  if (__NSCFURLSessionTask) {
    hooks.push(hookResume(__NSCFURLSessionTask));
    const ch = hookTaskCompletion(__NSCFURLSessionTask);
    if (ch) hooks.push(ch);
  }

  if (NSURLSessionTask) {
    hooks.push(hookResume(NSURLSessionTask));
    const ch = hookTaskCompletion(NSURLSessionTask);
    if (ch) hooks.push(ch);
  }

  if (__NSCFLocalSessionTask) {
    const dr = hookResume(__NSCFLocalSessionTask);
    if (dr) hooks.push(dr);
  }

  hookSessionAsyncMethods();
  hookConnectionAsyncMethods();
  hookWebSocketMethods();
  hookSessionCreation();
  hookConnectionCreation();
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
