import ObjC from "frida-objc-bridge";

import type {
  NSObject,
  NSString,
  NSData,
  NSMutableData,
  NSError,
  NSURL,
  NSURLRequest,
  NSURLResponse,
  NSHTTPURLResponse,
  NSURLSessionTask,
  NSURLSessionDataTask,
  NSURLSessionDownloadTask,
  NSURLSessionWebSocketTask,
  NSURLSessionWebSocketMessage,
  NSFileManager,
  NSNumber,
} from "@/fruity/typings.js";
import { wrapObjC } from "@/fruity/typings.js";
import { getGlobalExport } from "@/lib/polyfill.js";

const subject = "http";

function nextRequestId(): string {
  return ObjC.classes.NSUUID.UUID().UUIDString().toString();
}

interface TaskBoundData {
  id?: string;
}

interface NetworkEvent {
  event: string;
  requestId: string;
  timestamp: number;
  [key: string]: unknown;
}

interface RequestState {
  request: NSURLRequest | null;
  dataAccumulator: NSMutableData | null;
}

const hooks: InvocationListener[] = [];

function emitNetworkEvent(event: NetworkEvent): void {
  send({ subject, ...event });
}

const requestStates = new Map<string, RequestState>();

function getRequestState(requestId: string): RequestState {
  let state = requestStates.get(requestId);
  if (!state) {
    state = { request: null, dataAccumulator: null };
    requestStates.set(requestId, state);
  }
  return state;
}

function removeRequestState(requestId: string): void {
  requestStates.delete(requestId);
}

function getOrAssignTaskId(task: NSURLSessionTask): string {
  const metadata = ObjC.getBoundData(task) as TaskBoundData;
  let id = metadata?.id;
  if (!id) {
    id = nextRequestId();
    ObjC.bind(task, { id } as TaskBoundData);
  }
  return id;
}

function classFromSymbol(symbol: string): ObjC.Object | null {
  const index = symbol.indexOf(" ");
  if (index === -1) return null;
  const className = symbol.substring(2, index);
  return ObjC.classes[className] || null;
}

interface SerializedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

interface SerializedResponse {
  url?: string;
  mimeType?: string;
  expectedContentLength: number;
  statusCode?: number;
  headers?: Record<string, string>;
}

function serializeRequest(request: NSURLRequest): SerializedRequest {
  const url = request.URL()?.absoluteString().toString();
  const method = request.HTTPMethod()?.toString() || "GET";
  const bodyData = request.HTTPBody();
  const body = bodyData
    ? (ObjC.classes.NSString.alloc().initWithData_encoding_(bodyData, 4) as
        | NSString
        | undefined)
    : undefined;

  const allHeaders = request.allHTTPHeaderFields();
  const headers: Record<string, string> = {};
  if (allHeaders) {
    const keys = allHeaders.allKeys();
    const count = keys.count();
    for (let i = 0; i < count; i++) {
      const key = keys.objectAtIndex_(i);
      const value = allHeaders.objectForKey_(key);
      if (value) {
        headers[key.toString()] = value.toString();
      }
    }
  }

  return { url, method, headers, body: body?.toString() };
}

function serializeResponse(response: NSURLResponse): SerializedResponse {
  const url = response.URL()?.absoluteString().toString();
  const mimeType = response.MIMEType()?.toString();
  const expectedContentLength = response.expectedContentLength();

  const serialized: SerializedResponse = { expectedContentLength };
  if (url) serialized.url = url;
  if (mimeType) serialized.mimeType = mimeType;

  if (response.respondsToSelector_(ObjC.selector("statusCode"))) {
    const httpResponse = response as NSHTTPURLResponse;
    serialized.statusCode = httpResponse.statusCode();

    const headerFields = httpResponse.allHeaderFields();
    const headers: Record<string, string> = {};
    if (headerFields) {
      const keys = headerFields.allKeys();
      const count = keys.count();
      for (let i = 0; i < count; i++) {
        const key = keys.objectAtIndex_(i);
        const value = headerFields.objectForKey_(key);
        if (value) {
          headers[key.toString()] = value.toString();
        }
      }
    }
    serialized.headers = headers;
  }

  return serialized;
}

function serializeBody(
  data: NSData | null,
  maxSize: number = 10000,
): string | null {
  if (!data) return null;
  try {
    const length = data.length();
    if (length === 0) return null;
    if (length > maxSize) return `<${length} bytes, too large>`;

    const bodyString = ObjC.classes.NSString.alloc().initWithData_encoding_(
      data,
      4,
    ) as NSString | null;
    return bodyString ? bodyString.toString() : `<${length} bytes, binary>`;
  } catch (e) {
    return `<error: ${e}>`;
  }
}

function recordRequestWillBeSent(
  requestId: string,
  request: NSURLRequest,
  redirectResponse: NSURLResponse | null,
): void {
  const event: NetworkEvent = {
    event: "requestWillBeSent",
    requestId,
    timestamp: Date.now(),
    request: serializeRequest(request),
  };
  if (redirectResponse) {
    event.redirectResponse = serializeResponse(redirectResponse);
  }
  emitNetworkEvent(event);
}

function recordResponseReceived(
  requestId: string,
  response: NSURLResponse,
): void {
  emitNetworkEvent({
    event: "responseReceived",
    requestId,
    timestamp: Date.now(),
    response: serializeResponse(response),
  });
}

function recordDataReceived(
  requestId: string,
  dataLength: number | string,
): void {
  emitNetworkEvent({
    event: "dataReceived",
    requestId,
    timestamp: Date.now(),
    dataLength:
      typeof dataLength === "string" ? dataLength : String(dataLength),
  });
}

function recordLoadingFinished(
  requestId: string,
  responseBody: NSData | null,
): void {
  emitNetworkEvent({
    event: "loadingFinished",
    requestId,
    timestamp: Date.now(),
    responseBody: serializeBody(responseBody),
  });
}

function recordLoadingFailed(requestId: string, error: NSError): void {
  emitNetworkEvent({
    event: "loadingFailed",
    requestId,
    timestamp: Date.now(),
    error: error.toString(),
  });
}

function recordMechanism(mechanism: string, requestId: string): void {
  emitNetworkEvent({
    event: "mechanism",
    requestId,
    timestamp: Date.now(),
    mechanism,
  });
}

function recordWebSocketMessage(
  type: "send" | "receive",
  task: NSURLSessionWebSocketTask,
  message: NSURLSessionWebSocketMessage,
  error?: NSError | null,
): void {
  const event: NetworkEvent = {
    event: `webSocket${type === "send" ? "Send" : "Receive"}`,
    requestId: task.taskIdentifier().toString(),
    timestamp: Date.now(),
    messageType: message.type() === 0 ? "data" : "string",
  };

  const msgData = message.data();
  const msgString = message.string();
  if (message.type() === 0 && msgData) {
    event.dataLength = msgData.length();
  } else if (message.type() === 1 && msgString) {
    event.message = msgString.toString();
  }

  if (error) {
    event.error = error.toString();
  }

  emitNetworkEvent(event);
}

function hookResume(klass: ObjC.Object) {
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

function hookDelegateMethods() {
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
        const state = getRequestState(requestId);

        if (!state.dataAccumulator) {
          state.dataAccumulator =
            ObjC.classes.NSMutableData.alloc().init() as NSMutableData;
        }

        state.dataAccumulator.appendData_(data);
        recordDataReceived(requestId, data.length());
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
          const state = getRequestState(requestId);
          recordLoadingFinished(requestId, state.dataAccumulator);
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

          if (!state.dataAccumulator) {
            state.dataAccumulator =
              ObjC.classes.NSMutableData.alloc().init() as NSMutableData;

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
        const downloadTask = wrapObjC<NSURLSessionDownloadTask>(args[3]);
        const requestId = getOrAssignTaskId(downloadTask);
        const state = getRequestState(requestId);

        if (!args[4].isNull()) {
          const fileURL = wrapObjC<NSURL>(args[4]);

          const filemgr =
            ObjC.classes.NSFileManager.defaultManager() as NSFileManager;
          const size = filemgr
            .attributesOfItemAtPath_error_(fileURL.path() as NSString, NULL)!
            .objectForKey_("NSFileSize" as unknown as NSString) as NSNumber;
          if (size.intValue() < 1024 * 1024) {
            const fileData = ObjC.classes.NSData.dataWithContentsOfURL_(
              fileURL,
            ) as NSData;

            if (fileData) {
              state.dataAccumulator =
                ObjC.classes.NSMutableData.alloc().initWithData_(
                  fileData,
                ) as NSMutableData;
            }
          }
        }
      },
    },
  };

  const resolver = new ApiResolver("objc");
  const fmt = (sel: string) => `-[* ${sel}]`;

  for (const [sel, handler] of Object.entries(delegateMethodHandlers)) {
    for (const match of resolver.enumerateMatches(fmt(sel))) {
      const clazz = classFromSymbol(match.name);
      if (!clazz) continue;

      const method = clazz["- " + sel] as ObjC.ObjectMethod;
      hooks.push(Interceptor.attach(method.implementation, handler));
    }
  }
}

interface CompletionBoundData {
  requestId?: string;
  isDownload?: boolean;
}

function hookNSURLSessionAsyncMethods() {
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
          } else {
            if (!response.isNull()) {
              recordResponseReceived(rid, wrapObjC<NSURLResponse>(response));
            }
            if (isDownload) {
              let fileData: NSData | null = null;
              if (!first.isNull()) {
                fileData = ObjC.classes.NSData.dataWithContentsOfURL_(
                  wrapObjC<NSURL>(first),
                ) as NSData | null;
              }
              recordLoadingFinished(rid, fileData);
            } else {
              const nsdata = first.isNull() ? null : wrapObjC<NSData>(first);
              if (nsdata) {
                recordDataReceived(rid, nsdata.length());
              }
              recordLoadingFinished(rid, nsdata);
            }
          }
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

function getOrAssignConnectionId(connection: ObjC.Object): string {
  const metadata = ObjC.getBoundData(connection) as TaskBoundData;
  let id = metadata?.id;
  if (!id) {
    id = nextRequestId();
    ObjC.bind(connection, { id } as TaskBoundData);
  }
  return id;
}

function hookNSURLConnectionDelegateMethods() {
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
        const state = getRequestState(requestId);
        state.dataAccumulator =
          ObjC.classes.NSMutableData.alloc().init() as NSMutableData;
        recordResponseReceived(requestId, response);
      },
    },
    "connection:didReceiveData:": {
      onEnter(args) {
        const connection = new ObjC.Object(args[2]);
        const data = wrapObjC<NSData>(args[3]);
        const requestId = getOrAssignConnectionId(connection);
        const state = getRequestState(requestId);

        if (!state.dataAccumulator) {
          state.dataAccumulator =
            ObjC.classes.NSMutableData.alloc().init() as NSMutableData;
        }
        state.dataAccumulator.appendData_(data);
        recordDataReceived(requestId, data.length());
      },
    },
    "connectionDidFinishLoading:": {
      onEnter(args) {
        const connection = new ObjC.Object(args[2]);
        const requestId = getOrAssignConnectionId(connection);
        const state = getRequestState(requestId);
        recordLoadingFinished(requestId, state.dataAccumulator);
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

  const resolver = new ApiResolver("objc");
  const fmt = (sel: string) => `-[* ${sel}]`;

  for (const [sel, handler] of Object.entries(delegateMethodHandlers)) {
    for (const match of resolver.enumerateMatches(fmt(sel))) {
      const clazz = classFromSymbol(match.name);
      if (!clazz) continue;

      const method = clazz["- " + sel] as ObjC.ObjectMethod;
      hooks.push(Interceptor.attach(method.implementation, handler));
    }
  }
}

function hookNSURLConnectionAsyncMethods() {
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
                  } else {
                    if (!response.isNull()) {
                      recordResponseReceived(
                        rid,
                        wrapObjC<NSURLResponse>(response),
                      );
                    }
                    const nsdata = data.isNull()
                      ? null
                      : wrapObjC<NSData>(data);
                    if (nsdata) {
                      recordDataReceived(rid, nsdata.length());
                    }
                    recordLoadingFinished(rid, nsdata);
                  }
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

function hookWebSocketMethods() {
  const classes = [
    ObjC.classes.__NSURLSessionWebSocketTask,
    ObjC.classes.NSURLSessionWebSocketTask,
  ].filter(Boolean);

  const hookedSendInvokers = new Set<string>();
  const hookedRecvInvokers = new Set<string>();

  for (const clazz of classes) {
    // -sendMessage:completionHandler:
    const sendMethod = clazz["- sendMessage:completionHandler:"] as
      | ObjC.ObjectMethod
      | undefined;
    if (sendMethod) {
      hooks.push(
        Interceptor.attach(sendMethod.implementation, {
          onEnter(args) {
            const task = wrapObjC<NSURLSessionWebSocketTask>(args[0]);
            const message = wrapObjC<NSURLSessionWebSocketMessage>(args[2]);
            recordWebSocketMessage("send", task, message);

            // Hook completion to capture send errors
            const blockPtr = args[3];
            if (blockPtr.isNull()) return;

            const invokePtr = blockPtr.add(0x10).readPointer();
            const key = invokePtr.toString();
            if (!hookedSendInvokers.has(key)) {
              hookedSendInvokers.add(key);
              hooks.push(
                Interceptor.attach(invokePtr, {
                  onEnter(innerArgs) {
                    const error = innerArgs[1];
                    if (!error.isNull()) {
                      // Re-emit with error info attached
                      const block = new ObjC.Object(innerArgs[0]);
                      const meta = ObjC.getBoundData(block) as {
                        task?: NSURLSessionWebSocketTask;
                        message?: NSURLSessionWebSocketMessage;
                      };
                      if (meta?.task && meta?.message) {
                        recordWebSocketMessage(
                          "send",
                          meta.task,
                          meta.message,
                          wrapObjC<NSError>(error),
                        );
                      }
                    }
                  },
                }),
              );
            }

            const block = new ObjC.Object(blockPtr);
            ObjC.bind(block, { task, message });
          },
        }),
      );
    }

    // -receiveMessageWithCompletionHandler:
    const recvMethod = clazz["- receiveMessageWithCompletionHandler:"] as
      | ObjC.ObjectMethod
      | undefined;
    if (recvMethod) {
      hooks.push(
        Interceptor.attach(recvMethod.implementation, {
          onEnter(args) {
            const task = wrapObjC<NSURLSessionWebSocketTask>(args[0]);
            const blockPtr = args[2];
            if (blockPtr.isNull()) return;

            const invokePtr = blockPtr.add(0x10).readPointer();
            const key = invokePtr.toString();
            if (!hookedRecvInvokers.has(key)) {
              hookedRecvInvokers.add(key);
              hooks.push(
                Interceptor.attach(invokePtr, {
                  onEnter(innerArgs) {
                    const message = innerArgs[1];
                    const error = innerArgs[2];
                    if (!message.isNull()) {
                      const block = new ObjC.Object(innerArgs[0]);
                      const meta = ObjC.getBoundData(block) as {
                        task?: NSURLSessionWebSocketTask;
                      };
                      if (meta?.task) {
                        recordWebSocketMessage(
                          "receive",
                          meta.task,
                          wrapObjC<NSURLSessionWebSocketMessage>(message),
                          error.isNull() ? null : wrapObjC<NSError>(error),
                        );
                      }
                    }
                  },
                }),
              );
            }

            const block = new ObjC.Object(blockPtr);
            ObjC.bind(block, { task });
          },
        }),
      );
    }
  }
}

function hookRespondsToSelector() {
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

  hookNSURLSessionAsyncMethods();
  hookDelegateMethods();
  hookNSURLConnectionDelegateMethods();
  hookNSURLConnectionAsyncMethods();
  hookWebSocketMethods();
  hookRespondsToSelector();
}

export function stop() {
  for (const hook of hooks) {
    hook.detach();
  }
  hooks.length = 0;
}
