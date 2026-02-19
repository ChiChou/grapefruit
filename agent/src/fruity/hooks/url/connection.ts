import ObjC from "frida-objc-bridge";

import type {
  NSObject,
  NSURLRequest,
  NSURLResponse,
  NSData,
  NSError,
} from "@/fruity/typings.js";
import { wrapObjC } from "@/fruity/typings.js";

import {
  hooks,
  type TaskBoundData,
  nextRequestId,
  getRequestState,
  removeRequestState,
  recordRequestWillBeSent,
  recordResponseReceived,
  recordDataReceived,
  recordLoadingFinished,
  recordLoadingFailed,
  recordMechanism,
} from "./common.js";
import { hookDelegateClass } from "./lazy.js";

const delegateMethodHandlers: Record<string, InvocationListenerCallbacks> = {
  "connection:willSendRequest:redirectResponse:": {
    onEnter(args) {
      const delegate = wrapObjC<NSObject>(args[0]);
      const connection = new ObjC.Object(args[2]);
      const request = wrapObjC<NSURLRequest>(args[3]);
      const response = args[4].isNull()
        ? null
        : wrapObjC<NSURLResponse>(args[4]);

      const requestId = getOrAssignConnectionId(connection);
      const state = getRequestState(requestId);
      state.request = request;

      recordRequestWillBeSent(requestId, request, response);
      recordMechanism(
        `NSURLConnection (delegate: ${delegate.$className})`,
        requestId,
      );
    },
  },
  "connection:didReceiveResponse:": {
    onEnter(args) {
      const connection = new ObjC.Object(args[2]);
      const response = wrapObjC<NSURLResponse>(args[3]);
      const requestId = getOrAssignConnectionId(connection);
      recordResponseReceived(requestId, response);
    },
  },
  "connection:didReceiveData:": {
    onEnter(args) {
      const connection = new ObjC.Object(args[2]);
      const data = wrapObjC<NSData>(args[3]);
      const requestId = getOrAssignConnectionId(connection);
      const len = data.length();
      const chunk = len > 0 ? data.bytes().readByteArray(len) : null;
      recordDataReceived(requestId, len, chunk);
    },
  },
  "connectionDidFinishLoading:": {
    onEnter(args) {
      const connection = new ObjC.Object(args[2]);
      const requestId = getOrAssignConnectionId(connection);
      recordLoadingFinished(requestId);
      removeRequestState(requestId);
    },
  },
  "connection:didFailWithError:": {
    onEnter(args) {
      const connection = new ObjC.Object(args[2]);
      const requestId = getOrAssignConnectionId(connection);
      const state = getRequestState(requestId);
      if (state.request) {
        recordLoadingFailed(requestId, wrapObjC<NSError>(args[3]));
      }
      removeRequestState(requestId);
    },
  },
};

function getOrAssignConnectionId(connection: ObjC.Object): string {
  const metadata = ObjC.getBoundData(connection) as TaskBoundData;
  let id = metadata?.id;
  if (!id) {
    id = nextRequestId();
    ObjC.bind(connection, { id } as TaskBoundData);
  }
  return id;
}

export function hookConnectionCreation() {
  const { NSURLConnection } = ObjC.classes;
  if (!NSURLConnection) return;

  const initSelectors = [
    "initWithRequest:delegate:",
    "initWithRequest:delegate:startImmediately:",
  ];

  for (const sel of initSelectors) {
    const method = NSURLConnection["- " + sel] as
      | ObjC.ObjectMethod
      | undefined;
    if (!method) continue;

    hooks.push(
      Interceptor.attach(method.implementation, {
        onEnter(args) {
          // args: self, _cmd, request, delegate[, startImmediately]
          if (args[3].isNull()) return;

          const delegate = new ObjC.Object(args[3]);
          hooks.push(...hookDelegateClass(delegate, delegateMethodHandlers));
        },
      }),
    );
  }
}

export function hookAsyncMethods() {
  const { NSURLConnection } = ObjC.classes;
  if (!NSURLConnection) return;

  // +sendAsynchronousRequest:queue:completionHandler:
  const asyncSel = "sendAsynchronousRequest:queue:completionHandler:";
  const asyncMethod = NSURLConnection["+ " + asyncSel] as
    | ObjC.ObjectMethod
    | undefined;

  if (asyncMethod) {
    const hookedInvokers = new Set<string>();

    hooks.push(
      Interceptor.attach(asyncMethod.implementation, {
        onEnter(args) {
          // args: self, _cmd, request, queue, completionHandler
          const request = wrapObjC<NSURLRequest>(args[2]);
          const blockPtr = args[4];
          if (blockPtr.isNull()) return;

          const requestId = nextRequestId();
          recordRequestWillBeSent(requestId, request, null);
          recordMechanism(
            "+[NSURLConnection sendAsynchronousRequest:queue:completionHandler:]",
            requestId,
          );

          // Hook the block's invoke function
          const invokePtr = blockPtr.add(0x10).readPointer();
          const key = invokePtr.toString();
          if (!hookedInvokers.has(key)) {
            hookedInvokers.add(key);
            hooks.push(
              Interceptor.attach(invokePtr, {
                onEnter(innerArgs) {
                  const block = new ObjC.Object(innerArgs[0]);
                  const meta = ObjC.getBoundData(block) as TaskBoundData;
                  if (!meta?.id) return;

                  const rid = meta.id;
                  const response = innerArgs[1];
                  const data = innerArgs[2];
                  const error = innerArgs[3];

                  if (!error.isNull()) {
                    recordLoadingFailed(rid, wrapObjC<NSError>(error));
                    return;
                  }

                  if (!response.isNull()) {
                    recordResponseReceived(
                      rid,
                      wrapObjC<NSURLResponse>(response),
                    );
                  }
                  const nsdata = data.isNull() ? null : wrapObjC<NSData>(data);
                  if (nsdata) {
                    const len = nsdata.length();
                    const chunk =
                      len > 0 ? nsdata.bytes().readByteArray(len) : null;
                    recordDataReceived(rid, len, chunk);
                  }
                  recordLoadingFinished(rid);
                },
              }),
            );
          }

          // Bind request ID to the block
          const block = new ObjC.Object(blockPtr);
          ObjC.bind(block, { id: requestId } as TaskBoundData);
        },
      }),
    );
  }
}
