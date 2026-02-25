import ObjC from "frida-objc-bridge";

import type {
  NSObject,
  NSURLSessionTask,
  NSURLSessionDataTask,
  NSURLSessionDownloadTask,
  NSURLRequest,
  NSURLResponse,
  NSData,
  NSError,
  NSURL,
} from "@/fruity/typings.js";
import { wrapObjC } from "@/fruity/typings.js";
import { getGlobalExport } from "@/lib/polyfill.js";

import {
  hooks,
  getMethodImp,
  type TaskBoundData,
  nextRequestId,
  getOrAssignTaskId,
  getRequestState,
  hasRequestState,
  removeRequestState,
  recordRequestWillBeSent,
  recordResponseReceived,
  recordDataReceived,
  recordLoadingFinished,
  recordLoadingFailed,
  recordMechanism,
} from "./common.js";
import { hookDelegateClass, injectRespondsToSelector } from "./lazy.js";

function streamFileData(fileURL: NSURL, requestId: string) {
  const handle = ObjC.classes.NSFileHandle.fileHandleForReadingAtPath_(
    fileURL.path(),
  );
  if (!handle) return;

  const chunkSize = 256 * 1024;
  try {
    while (true) {
      const data = handle.readDataOfLength_(chunkSize) as NSData;
      if (!data) break;
      const len = data.length();
      if (len <= 0) break;
      const chunk = data.bytes().readByteArray(len);
      recordDataReceived(requestId, len, chunk);
    }
  } finally {
    handle.closeFile();
  }
}

const delegateMethodHandlers: Record<string, InvocationListenerCallbacks> = {
  "URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:": {
    onEnter(args) {
      if (args[4].isNull() || args[5].isNull()) return;
      const task = wrapObjC<NSURLSessionTask>(args[3]);
      const redirectResponse = wrapObjC<NSURLResponse>(args[4]);
      const newRequest = wrapObjC<NSURLRequest>(args[5]);

      // Finish the current request with the redirect (301/302) response
      const currentId = getOrAssignTaskId(task);
      recordResponseReceived(currentId, redirectResponse);
      recordLoadingFinished(currentId);
      removeRequestState(currentId);

      // New ID for the redirected request, rebind the task
      const newId = nextRequestId();
      ObjC.bind(task, { id: newId } as TaskBoundData);
      getRequestState(newId);
      recordRequestWillBeSent(newId, newRequest, redirectResponse);
    },
  },
  "URLSession:dataTask:didReceiveResponse:completionHandler:": {
    onEnter(args) {
      if (args[4].isNull() || args[5].isNull()) return;
      const delegate = wrapObjC<NSObject>(args[2]);
      const dataTask = wrapObjC<NSURLSessionDataTask>(args[3]);
      const requestId = getOrAssignTaskId(dataTask);
      recordMechanism(
        `NSURLSessionDataTask (delegate: ${delegate.$className})`,
        requestId,
      );
      recordResponseReceived(requestId, wrapObjC<NSURLResponse>(args[4]));
    },
  },
  "URLSession:dataTask:didReceiveData:": {
    onEnter(args) {
      const dataTask = wrapObjC<NSURLSessionDataTask>(args[3]);
      const data = wrapObjC<NSData>(args[4]);
      const requestId = getOrAssignTaskId(dataTask);
      const len = data.length();
      const chunk = len > 0 ? data.bytes().readByteArray(len) : null;
      recordDataReceived(requestId, len, chunk);
    },
  },
  "URLSession:task:didCompleteWithError:": {
    onEnter(args) {
      const task = wrapObjC<NSURLSessionTask>(args[3]);
      const requestId = getOrAssignTaskId(task);

      // Always emit response from task — covers completion handler tasks
      // where didReceiveResponse: may not fire
      const response = task.response();
      if (response) {
        recordResponseReceived(requestId, response);
      }

      if (!args[4].isNull()) {
        recordLoadingFailed(requestId, wrapObjC<NSError>(args[4]));
      } else {
        recordLoadingFinished(requestId);
      }
      removeRequestState(requestId);
    },
  },
  "URLSession:dataTask:didBecomeDownloadTask:": {
    onEnter(args) {
      const dataTask = wrapObjC<NSURLSessionDataTask>(args[3]);
      const downloadTask = wrapObjC<NSURLSessionDownloadTask>(args[4]);
      const dataTaskId = getOrAssignTaskId(dataTask);
      ObjC.bind(downloadTask, { id: dataTaskId } as TaskBoundData);
    },
  },
  "URLSession:downloadTask:didWriteData:totalBytesWritten:totalBytesExpectedToWrite:":
    {
      onEnter(args) {
        const delegate = wrapObjC<NSObject>(args[2]);
        const downloadTask = wrapObjC<NSURLSessionDownloadTask>(args[3]);
        const requestId = getOrAssignTaskId(downloadTask);
        const state = getRequestState(requestId);

        if (!state.mechanismRecorded) {
          state.mechanismRecorded = true;

          const response = downloadTask.response();
          if (response) {
            recordResponseReceived(requestId, response);
          }

          recordMechanism(
            `NSURLSessionDownloadTask (delegate: ${delegate.$className})`,
            requestId,
          );
        }
        recordDataReceived(requestId, args[4].toString());
      },
    },
  "URLSession:downloadTask:didFinishDownloadingToURL:": {
    onEnter(args) {
      if (args[4].isNull()) return;

      const downloadTask = wrapObjC<NSURLSessionDownloadTask>(args[3]);
      const requestId = getOrAssignTaskId(downloadTask);
      streamFileData(wrapObjC<NSURL>(args[4]), requestId);
    },
  },
};

export function hookResume(klass: ObjC.Object) {
  const imp = getMethodImp(klass, "resume", false)!;
  return Interceptor.attach(imp, {
    onEnter(args) {
      const task = wrapObjC<NSURLSessionTask>(args[0]);

      const avClass = ObjC.classes.AVAggregateAssetDownloadTask;
      if (avClass && task.isKindOfClass_(avClass)) {
        return;
      }

      // Lazily hook delegate for pre-existing sessions
      try {
        const delegate = task.session().delegate();
        if (delegate && !delegate.handle.isNull()) {
          hooks.push(...hookDelegateClass(delegate, delegateMethodHandlers));
          const rtsHook = injectRespondsToSelector(delegate);
          if (rtsHook) hooks.push(rtsHook);
        }
      } catch (_e) {
        // session may not expose delegate
      }

      // Pre-parse HTTP body to avoid thread safety issues
      const currentRequest = task.currentRequest();
      if (currentRequest) {
        currentRequest.HTTPBody();
      }

      const requestId = getOrAssignTaskId(task);
      const state = getRequestState(requestId);
      if (!state.request && currentRequest) {
        state.request = currentRequest;
        recordRequestWillBeSent(requestId, currentRequest, null);
      }
    },
  });
}

/**
 * Fallback: hook setState: on the task class to catch completion
 * for tasks whose session has no delegate and no completion handler.
 * Only emits if no delegate/CH already recorded the event
 * (checked via hasRequestState — it's removed by delegate/CH handlers).
 */
export function hookTaskCompletion(klass: ObjC.Object) {
  const imp = getMethodImp(klass, "setState:", false);
  if (!imp) return null;

  return Interceptor.attach(imp, {
    onEnter(args) {
      // NSURLSessionTaskStateCompleted = 3
      if (args[2].toInt32() !== 3) return;

      const task = wrapObjC<NSURLSessionTask>(args[0]);
      const bound = ObjC.getBoundData(task) as TaskBoundData;
      if (!bound?.id) return;

      const requestId = bound.id;
      // Already handled by delegate or completion handler
      if (!hasRequestState(requestId)) return;

      const response = task.response();
      if (response) {
        recordResponseReceived(requestId, response);
      }

      const error = task.error();
      if (error) {
        recordLoadingFailed(requestId, error as unknown as NSError);
      } else {
        recordLoadingFinished(requestId);
      }
      removeRequestState(requestId);
    },
  });
}

export function hookSessionCreation() {
  const sel = "sessionWithConfiguration:delegate:delegateQueue:";
  const classes = [
    ObjC.classes.NSURLSession,
    ObjC.classes.__NSURLSessionLocal,
  ].filter(Boolean);

  for (const clazz of classes) {
    const imp = getMethodImp(clazz, sel, true);
    if (!imp) continue;

    hooks.push(
      Interceptor.attach(imp, {
        onEnter(args) {
          // args: self, _cmd, configuration, delegate, delegateQueue
          if (args[3].isNull()) return;

          const delegate = new ObjC.Object(args[3]);
          hooks.push(...hookDelegateClass(delegate, delegateMethodHandlers));
          const rtsHook = injectRespondsToSelector(delegate);
          if (rtsHook) hooks.push(rtsHook);
        },
      }),
    );
  }
}

interface CompletionBoundData {
  requestId?: string;
  isDownload?: boolean;
}

export function hookAsyncMethods() {
  const downloadSelectors = new Set([
    "downloadTaskWithRequest:completionHandler:",
    "downloadTaskWithResumeData:completionHandler:",
    "downloadTaskWithURL:completionHandler:",
  ]);

  const selectorHandlerIndex: Record<string, number> = {
    "dataTaskWithRequest:completionHandler:": 3,
    "dataTaskWithURL:completionHandler:": 3,
    "downloadTaskWithRequest:completionHandler:": 3,
    "downloadTaskWithResumeData:completionHandler:": 3,
    "downloadTaskWithURL:completionHandler:": 3,
    "uploadTaskWithRequest:fromData:completionHandler:": 4,
    "uploadTaskWithRequest:fromFile:completionHandler:": 4,
  };

  function mechanismForSelector(sel: string): string {
    if (sel.startsWith("download"))
      return "NSURLSessionDownloadTask (completionHandler)";
    if (sel.startsWith("upload"))
      return "NSURLSessionUploadTask (completionHandler)";
    return "NSURLSessionDataTask (completionHandler)";
  }

  // Force-copy blocks to heap so the pointer stays stable for ObjC.bind.
  // Stack blocks get a new address when the runtime copies them; by
  // pre-copying we ensure args[0] in the invoke matches what we bound to.
  const blockCopy = new NativeFunction(
    getGlobalExport("_Block_copy"),
    "pointer",
    ["pointer"],
  );
  const blockRelease = new NativeFunction(
    getGlobalExport("_Block_release"),
    "void",
    ["pointer"],
  );

  const hookedInvokers = new Set<string>();

  function hookCompletionInvoke(blockPtr: NativePointer) {
    const invokePtr = blockPtr.add(0x10).readPointer();
    const key = invokePtr.toString();
    if (hookedInvokers.has(key)) return;
    hookedInvokers.add(key);

    hooks.push(
      Interceptor.attach(invokePtr, {
        onEnter(args) {
          const block = new ObjC.Object(args[0]);
          const metadata = ObjC.getBoundData(block) as CompletionBoundData;
          if (!metadata?.requestId) return;

          const rid = metadata.requestId;
          const isDownload = metadata.isDownload ?? false;
          const first = args[1];
          const response = args[2];
          const error = args[3];

          if (!error.isNull()) {
            recordLoadingFailed(rid, wrapObjC<NSError>(error));
            removeRequestState(rid);
            return;
          }

          if (!response.isNull()) {
            recordResponseReceived(rid, wrapObjC<NSURLResponse>(response));
          }

          if (isDownload && !first.isNull()) {
            streamFileData(wrapObjC<NSURL>(first), rid);
          } else if (!first.isNull()) {
            const nsdata = wrapObjC<NSData>(first);
            const len = nsdata.length();
            const chunk = len > 0 ? nsdata.bytes().readByteArray(len) : null;
            recordDataReceived(rid, len, chunk);
          }

          recordLoadingFinished(rid);
          removeRequestState(rid);
        },
      }),
    );
  }

  function hookSelector(clazz: ObjC.Object, sel: string) {
    const imp = getMethodImp(clazz, sel, false);
    if (!imp) return;

    const handlerIndex = selectorHandlerIndex[sel];
    const isDownload = downloadSelectors.has(sel);
    const mechanism = mechanismForSelector(sel);

    hooks.push(
      Interceptor.attach(imp, {
        onEnter(args) {
          if (args[handlerIndex].isNull()) return;

          // Copy the block to heap so the pointer is stable across
          // _Block_copy calls the runtime makes internally.
          const heapBlock = blockCopy(args[handlerIndex]) as NativePointer;
          args[handlerIndex] = heapBlock;

          hookCompletionInvoke(heapBlock);
          this.blockPtr = heapBlock;
          this.mechanism = mechanism;
          this.isDownload = isDownload;
        },
        onLeave(retval) {
          if (!this.blockPtr || retval.isNull()) return;

          // Release our extra retain — the method already retained the block
          blockRelease(this.blockPtr);

          const task = wrapObjC<NSURLSessionTask>(retval);
          const requestId = getOrAssignTaskId(task);

          const block = new ObjC.Object(this.blockPtr);
          ObjC.bind(block, {
            requestId,
            isDownload: this.isDownload,
          } as CompletionBoundData);

          const request = task.originalRequest();
          if (request) {
            recordRequestWillBeSent(requestId, request, null);
          }
          recordMechanism(this.mechanism, requestId);
        },
      }),
    );
  }

  function intercept(clazz: ObjC.Object) {
    for (const sel of Object.keys(selectorHandlerIndex)) {
      hookSelector(clazz, sel);
    }
  }

  const { NSURLSession, __NSURLSessionLocal } = ObjC.classes;
  if (NSURLSession) intercept(NSURLSession);
  if (__NSURLSessionLocal) intercept(__NSURLSessionLocal);
}
