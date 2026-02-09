import ObjC from "frida-objc-bridge";

import {
  type NSObject,
  type NSString,
  type NSData,
  type NSMutableData,
  type NSError,
  type NSURL,
  type NSURLRequest,
  type NSURLResponse,
  type NSHTTPURLResponse,
  type NSURLSessionTask,
  type NSURLSessionDataTask,
  type NSURLSessionDownloadTask,
  type NSFileManager,
  type NSNumber,
  wrapObjC,
} from "../typings.js";

const subject = "httplog";

function nextRequestId(): string {
  return ObjC.classes.NSUUID.UUID().UUIDString().toString();
}

interface TaskBoundData {
  id?: string;
}

interface NetworkEvent {
  type: string;
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
    type: "requestWillBeSent",
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
    type: "responseReceived",
    requestId,
    timestamp: Date.now(),
    response: serializeResponse(response),
  });
}

function recordDataReceived(requestId: string, dataLength: number): void {
  emitNetworkEvent({
    type: "dataReceived",
    requestId,
    timestamp: Date.now(),
    dataLength,
  });
}

function recordLoadingFinished(
  requestId: string,
  responseBody: NSData | null,
): void {
  emitNetworkEvent({
    type: "loadingFinished",
    requestId,
    timestamp: Date.now(),
    responseBody: serializeBody(responseBody),
  });
}

function recordLoadingFailed(requestId: string, error: NSError): void {
  emitNetworkEvent({
    type: "loadingFailed",
    requestId,
    timestamp: Date.now(),
    error: error.toString(),
  });
}

function recordMechanism(mechanism: string, requestId: string): void {
  emitNetworkEvent({
    type: "mechanism",
    requestId,
    timestamp: Date.now(),
    mechanism,
  });
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
          recordDataReceived(requestId, args[4].toInt32());
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
          hookCompletionInvoke(args[handlerIndex]);
          this.blockPtr = args[handlerIndex];
          this.mechanism = mechanism;
          this.isDownload = isDownload;
        },
        onLeave(retval) {
          if (!this.blockPtr || retval.isNull()) return;
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

export function start() {
  if (!ObjC.available) return;

  const { __NSCFURLSessionTask, NSURLSessionTask } = ObjC.classes;
  if (__NSCFURLSessionTask) {
    hooks.push(hookResume(__NSCFURLSessionTask));
  }

  if (NSURLSessionTask) {
    hooks.push(hookResume(NSURLSessionTask));
  }

  hookNSURLSessionAsyncMethods();
  hookDelegateMethods();
}

export function stop() {
  for (const hook of hooks) {
    hook.detach();
  }
  hooks.length = 0;
}
