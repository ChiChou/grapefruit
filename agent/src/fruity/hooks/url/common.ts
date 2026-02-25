import ObjC from "frida-objc-bridge";

import type {
  NSString,
  NSError,
  NSURLRequest,
  NSURLResponse,
  NSHTTPURLResponse,
  NSURLSessionTask,
  NSURLSessionWebSocketTask,
  NSURLSessionWebSocketMessage,
} from "@/fruity/typings.js";

const subject = "nsurl";

/**
 * Get the IMP for a method without going through frida-objc-bridge's
 * property accessor (which can trigger a JS error).
 * Returns null if the method doesn't exist on the class.
 */
export function getMethodImp(
  clazz: ObjC.Object,
  sel: string,
  isClassMethod: boolean,
): NativePointer | null {
  const methodPtr = isClassMethod
    ? ObjC.api.class_getClassMethod(clazz.handle, ObjC.selector(sel))
    : ObjC.api.class_getInstanceMethod(clazz.handle, ObjC.selector(sel));
  if ((methodPtr as NativePointer).isNull()) return null;
  return ObjC.api.method_getImplementation(methodPtr) as NativePointer;
}

export interface TaskBoundData {
  id?: string;
}

export interface SerializedRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

export interface SerializedResponse {
  url?: string;
  mimeType?: string;
  expectedContentLength: number;
  statusCode?: number;
  headers?: Record<string, string>;
}

interface NetworkEventBase {
  requestId: string;
  timestamp: number;
}

export interface RequestWillBeSentEvent extends NetworkEventBase {
  event: "requestWillBeSent";
  request: SerializedRequest;
  redirectResponse?: SerializedResponse;
}

export interface ResponseReceivedEvent extends NetworkEventBase {
  event: "responseReceived";
  response: SerializedResponse;
}

export interface DataReceivedEvent extends NetworkEventBase {
  event: "dataReceived";
  dataLength: string;
}

export interface LoadingFinishedEvent extends NetworkEventBase {
  event: "loadingFinished";
}

export interface LoadingFailedEvent extends NetworkEventBase {
  event: "loadingFailed";
  error: string;
}

export interface MechanismEvent extends NetworkEventBase {
  event: "mechanism";
  mechanism: string;
}

export interface WebSocketMessageEvent extends NetworkEventBase {
  event: "webSocketSend" | "webSocketReceive";
  messageType: "data" | "string";
  dataLength?: number;
  message?: string;
  error?: string;
}

export type NetworkEvent =
  | RequestWillBeSentEvent
  | ResponseReceivedEvent
  | DataReceivedEvent
  | LoadingFinishedEvent
  | LoadingFailedEvent
  | MechanismEvent
  | WebSocketMessageEvent;

export interface RequestState {
  request: NSURLRequest | null;
  mechanismRecorded?: boolean;
}

export const hooks: InvocationListener[] = [];

export function nextRequestId(): string {
  return ObjC.classes.NSUUID.UUID().UUIDString().toString();
}

export function emitNetworkEvent(
  event: NetworkEvent,
  data?: ArrayBuffer | null,
): void {
  if (data) return send({ subject, ...event }, data);
  send({ subject, ...event });
}

const requestStates = new Map<string, RequestState>();

export function getRequestState(requestId: string): RequestState {
  let state = requestStates.get(requestId);
  if (!state) {
    state = { request: null };
    requestStates.set(requestId, state);
  }
  return state;
}

export function hasRequestState(requestId: string): boolean {
  return requestStates.has(requestId);
}

export function removeRequestState(requestId: string): void {
  requestStates.delete(requestId);
}

export function getOrAssignTaskId(task: NSURLSessionTask): string {
  const metadata = ObjC.getBoundData(task) as TaskBoundData;
  let id = metadata?.id;
  if (!id) {
    id = nextRequestId();
    ObjC.bind(task, { id } as TaskBoundData);
  }
  return id;
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

export function recordRequestWillBeSent(
  requestId: string,
  request: NSURLRequest,
  redirectResponse: NSURLResponse | null,
): void {
  const event: RequestWillBeSentEvent = {
    event: "requestWillBeSent",
    requestId,
    timestamp: Date.now(),
    request: serializeRequest(request),
    ...(redirectResponse && {
      redirectResponse: serializeResponse(redirectResponse),
    }),
  };
  emitNetworkEvent(event);
}

export function recordResponseReceived(
  requestId: string,
  response: NSURLResponse,
): void {
  const event: ResponseReceivedEvent = {
    event: "responseReceived",
    requestId,
    timestamp: Date.now(),
    response: serializeResponse(response),
  };
  emitNetworkEvent(event);
}

export function recordDataReceived(
  requestId: string,
  dataLength: number | string,
  data?: ArrayBuffer | null,
): void {
  const event: DataReceivedEvent = {
    event: "dataReceived",
    requestId,
    timestamp: Date.now(),
    dataLength:
      typeof dataLength === "string" ? dataLength : String(dataLength),
  };
  emitNetworkEvent(event, data);
}

export function recordLoadingFinished(requestId: string): void {
  const event: LoadingFinishedEvent = {
    event: "loadingFinished",
    requestId,
    timestamp: Date.now(),
  };
  emitNetworkEvent(event);
}

export function recordLoadingFailed(requestId: string, error: NSError): void {
  const event: LoadingFailedEvent = {
    event: "loadingFailed",
    requestId,
    timestamp: Date.now(),
    error: error.toString(),
  };
  emitNetworkEvent(event);
}

export function recordMechanism(mechanism: string, requestId: string): void {
  const event: MechanismEvent = {
    event: "mechanism",
    requestId,
    timestamp: Date.now(),
    mechanism,
  };
  emitNetworkEvent(event);
}

export function recordWebSocketMessage(
  type: "send" | "receive",
  task: NSURLSessionWebSocketTask,
  message: NSURLSessionWebSocketMessage,
  error?: NSError | null,
): void {
  const event: WebSocketMessageEvent = {
    event: type === "send" ? "webSocketSend" : "webSocketReceive",
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
