import Java from "frida-java-bridge";

import { hookOkHttp } from "./okhttp.js";
import { hookHttpURLConnection } from "./urlconnection.js";
import { hookVolley } from "./volley.js";
import { hookWebSocket } from "./websocket.js";

export interface NetworkEvent {
  type: string;
  requestId: string;
  timestamp: number;
  [key: string]: unknown;
}

export interface RequestInfo {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  bodyLength?: number;
}

export interface ResponseInfo {
  url?: string;
  statusCode: number;
  statusMessage?: string;
  headers: Record<string, string>;
  contentType?: string;
  contentLength?: number;
}

export interface RequestState {
  request: RequestInfo | null;
  response: ResponseInfo | null;
  bodyChunks: ArrayBuffer[];
  bodyLength: number;
}

const requestStates = new Map<string, RequestState>();

export function getRequestState(requestId: string): RequestState {
  let state = requestStates.get(requestId);
  if (!state) {
    state = {
      request: null,
      response: null,
      bodyChunks: [],
      bodyLength: 0,
    };
    requestStates.set(requestId, state);
  }
  return state;
}

export function removeRequestState(requestId: string): void {
  requestStates.delete(requestId);
}

let requestCounter = 0;

export function nextRequestId(): string {
  return `req-${++requestCounter}-${Date.now()}`;
}

let _active = false;

export function emitNetworkEvent(event: NetworkEvent): void {
  if (!_active) return;
  send({ subject: "http", ...event });
}

export function emitBinaryData(
  requestId: string,
  data: ArrayBuffer,
  label: string,
): void {
  if (!_active) return;
  send(
    { subject: "http", type: "binaryData", requestId, timestamp: Date.now(), label },
    data,
  );
}

export const MAX_BODY_SIZE = 32 * 1024;

export function serializeBody(
  data: ArrayBuffer | number[] | null,
  maxSize: number = MAX_BODY_SIZE,
): string | null {
  if (!data) return null;

  if (Array.isArray(data)) {
    if (data.length === 0) return null;
    if (data.length > maxSize) return `<${data.length} bytes, too large>`;

    try {
      const chars: string[] = [];
      let isBinary = false;
      for (let i = 0; i < data.length; i++) {
        const b = data[i] & 0xff;
        if (b === 0 && i < 512) {
          isBinary = true;
          break;
        }
        chars.push(String.fromCharCode(b));
      }
      if (isBinary) return `<${data.length} bytes, binary>`;
      return chars.join("");
    } catch {
      return `<${data.length} bytes, decode error>`;
    }
  }

  const byteLength = data.byteLength;
  if (byteLength === 0) return null;
  if (byteLength > maxSize) return `<${byteLength} bytes, too large>`;

  try {
    const bytes = new Uint8Array(data);
    let isText = true;
    for (let i = 0; i < Math.min(bytes.length, 512); i++) {
      if (bytes[i] === 0) {
        isText = false;
        break;
      }
    }
    if (!isText) return `<${byteLength} bytes, binary>`;

    const decoder = new TextDecoder("utf-8", { fatal: false });
    return decoder.decode(data);
  } catch {
    return `<${byteLength} bytes, decode error>`;
  }
}

export function tryUse(className: string): Java.Wrapper | null {
  try {
    return Java.use(className);
  } catch {
    return null;
  }
}

export function identityHash(obj: Java.Wrapper): number {
  return Java.use("java.lang.System").identityHashCode(obj);
}

export function start(): void {
  if (_active) return;
  _active = true;
  Java.perform(() => {
    hookOkHttp();
    hookHttpURLConnection();
    hookVolley();
    hookWebSocket();
  });
}

export function stop(): void {
  _active = false;
}

export function status(): boolean {
  return _active;
}

export function available(): boolean {
  return Java.available;
}
