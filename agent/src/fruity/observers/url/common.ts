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

export { ObjC };

const subject = "http";

export interface TaskBoundData {
  id?: string;
}

export interface NetworkEvent {
  event: string;
  requestId: string;
  timestamp: number;
  [key: string]: unknown;
}

export interface RequestState {
  request: NSURLRequest | null;
  mechanismRecorded?: boolean;
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

export const hooks: InvocationListener[] = [];

export function nextRequestId(): string {
  return ObjC.classes.NSUUID.UUID().UUIDString().toString();
}

function emitNetworkEvent(
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

export function classFromSymbol(symbol: string): ObjC.Object | null {
  const index = symbol.indexOf(" ");
  if (index === -1) return null;
  const className = symbol.substring(2, index);
  return ObjC.classes[className] || null;
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

export function recordResponseReceived(
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

export function recordDataReceived(
  requestId: string,
  dataLength: number | string,
  data?: ArrayBuffer | null,
): void {
  emitNetworkEvent(
    {
      event: "dataReceived",
      requestId,
      timestamp: Date.now(),
      dataLength:
        typeof dataLength === "string" ? dataLength : String(dataLength),
    },
    data,
  );
}

export function recordLoadingFinished(requestId: string): void {
  emitNetworkEvent({
    event: "loadingFinished",
    requestId,
    timestamp: Date.now(),
  });
}

export function recordLoadingFailed(requestId: string, error: NSError): void {
  emitNetworkEvent({
    event: "loadingFailed",
    requestId,
    timestamp: Date.now(),
    error: error.toString(),
  });
}

export function recordMechanism(
  mechanism: string,
  requestId: string,
): void {
  emitNetworkEvent({
    event: "mechanism",
    requestId,
    timestamp: Date.now(),
    mechanism,
  });
}

export function recordWebSocketMessage(
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
