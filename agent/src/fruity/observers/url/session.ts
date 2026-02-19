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
  NSString,
  NSFileManager,
  NSNumber,
} from "@/fruity/typings.js";
import { wrapObjC } from "@/fruity/typings.js";
import { getGlobalExport } from "@/lib/polyfill.js";

import {
  hooks,
  type TaskBoundData,
  getOrAssignTaskId,
  getRequestState,
  removeRequestState,
  classFromSymbol,
  recordRequestWillBeSent,
  recordResponseReceived,
  recordDataReceived,
  recordLoadingFinished,
  recordLoadingFailed,
  recordMechanism,
} from "./common.js";

export function hookResume(klass: ObjC.Object) {
  return Interceptor.attach(klass["- resume"].implementation, {
    onEnter(args) {
      const task = wrapObjC<NSURLSessionTask>(args[0]);

      const avClass = ObjC.classes.AVAggregateAssetDownloadTask;
      if (avClass && task.isKindOfClass_(avClass)) {
        return;
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

export function hookDelegateMethods() {
  const delegateMethodHandlers: Record<string, InvocationListenerCallbacks> = {
    "URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:":
      {
        onEnter(args) {
          if (args[4].isNull() || args[5].isNull()) return;
          const requestId = getOrAssignTaskId(
            wrapObjC<NSURLSessionTask>(args[3]),
          );
          recordRequestWillBeSent(
            requestId,
            wrapObjC<NSURLRequest>(args[5]),
            wrapObjC<NSURLResponse>(args[4]),
          );
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
        const requestId = getOrAssignTaskId(dataTask);
        const data = wrapObjC<NSData>(args[4]);
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
        const fileURL = wrapObjC<NSURL>(args[4]);

        const filemgr =
          ObjC.classes.NSFileManager.defaultManager() as NSFileManager;
        const size = filemgr
          .attributesOfItemAtPath_error_(fileURL.path() as NSString, NULL)!
          .objectForKey_("NSFileSize" as unknown as NSString) as NSNumber;
        if (size.intValue() >= 1024 * 1024) return;

        const fileData = ObjC.classes.NSData.dataWithContentsOfURL_(
          fileURL,
        ) as NSData;
        if (!fileData) return;

        const len = fileData.length();
        const chunk = len > 0 ? fileData.bytes().readByteArray(len) : null;
        recordDataReceived(requestId, len, chunk);
      },
    },
  };

  const resolver = new ApiResolver("objc");
  const fmt = (sel: string) => `-[* ${sel}]`;

  for (const [sel, handler] of Object.entries(delegateMethodHandlers)) {
    for (const match of resolver.enumerateMatches(fmt(sel))) {
      const clazz = classFromSymbol(match.name);
      if (!clazz) continue;

      try {
        const method = clazz["- " + sel] as ObjC.ObjectMethod;
        hooks.push(Interceptor.attach(method.implementation, handler));
      } catch (e) {
        console.warn(`Failed to hook ${sel} on ${clazz.$className}:`);
        console.warn(e);
      }
    }
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

          if (isDownload) {
            if (!first.isNull()) {
              const fileData = ObjC.classes.NSData.dataWithContentsOfURL_(
                wrapObjC<NSURL>(first),
              ) as NSData | null;
              if (fileData) {
                const len = fileData.length();
                const chunk =
                  len > 0 ? fileData.bytes().readByteArray(len) : null;
                recordDataReceived(rid, len, chunk);
              }
            }
          } else {
            const nsdata = first.isNull() ? null : wrapObjC<NSData>(first);
            if (nsdata) {
              const len = nsdata.length();
              const chunk = len > 0 ? nsdata.bytes().readByteArray(len) : null;
              recordDataReceived(rid, len, chunk);
            }
          }

          recordLoadingFinished(rid);
          removeRequestState(rid);
        },
      }),
    );
  }

  function hookSelector(clazz: ObjC.Object, sel: string) {
    const method = clazz["- " + sel] as ObjC.ObjectMethod | undefined;
    if (!method) return;

    const handlerIndex = selectorHandlerIndex[sel];
    const isDownload = downloadSelectors.has(sel);
    const mechanism = mechanismForSelector(sel);

    hooks.push(
      Interceptor.attach(method.implementation, {
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

export function hookRespondsToSelector() {
  // Inject respondsToSelector: on delegate classes so they report YES for
  // URLSession:dataTask:didReceiveResponse:completionHandler: even when
  // they don't implement it. This forces the URL loading system to call
  // the delegate method, allowing our hooks to capture the response.
  const targetSel = ObjC.selector(
    "URLSession:dataTask:didReceiveResponse:completionHandler:",
  );

  const resolver = new ApiResolver("objc");
  const delegateSelectors = [
    "URLSession:dataTask:didReceiveData:",
    "URLSession:task:didCompleteWithError:",
  ];

  const injectedClasses = new Set<string>();

  for (const sel of delegateSelectors) {
    for (const match of resolver.enumerateMatches(`-[* ${sel}]`)) {
      const clazz = classFromSymbol(match.name);
      if (!clazz) continue;

      const className = clazz.$className;
      if (injectedClasses.has(className)) continue;

      // Skip if the class already implements didReceiveResponse:
      const existing = clazz[
        "- URLSession:dataTask:didReceiveResponse:completionHandler:"
      ] as ObjC.ObjectMethod | undefined;
      if (existing) continue;

      const rtsMethod = clazz["- respondsToSelector:"] as
        | ObjC.ObjectMethod
        | undefined;
      if (!rtsMethod) continue;

      injectedClasses.add(className);
      hooks.push(
        Interceptor.attach(rtsMethod.implementation, {
          onLeave(retval) {
            const sel = this.context as unknown as { x1: NativePointer };
            if (sel.x1.equals(targetSel)) {
              retval.replace(ptr(1));
            }
          },
        }),
      );
    }
  }
}
