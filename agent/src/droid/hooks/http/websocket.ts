import Java from "frida-java-bridge";
import { emitNetworkEvent, nextRequestId, tryUse, identityHash, MAX_BODY_SIZE } from "./common.js";

const wsRequestIds = new Map<number, string>();

function getWsRequestId(ws: Java.Wrapper): string {
  const hash = identityHash(ws);
  let rid = wsRequestIds.get(hash);
  if (!rid) {
    rid = nextRequestId();
    wsRequestIds.set(hash, rid);
  }
  return rid;
}

export function hookWebSocket(): void {
  const RealWebSocket = tryUse("okhttp3.internal.ws.RealWebSocket");
  if (!RealWebSocket) {
    console.log("OkHttp RealWebSocket not found — WebSocket hooks skipped");
    return;
  }

  try {
    const method = RealWebSocket.send.overload("java.lang.String");
    method.implementation = function (this: Java.Wrapper, text: Java.Wrapper) {
      const rid = getWsRequestId(this);
      const str = text !== null ? text.toString() : "";

      emitNetworkEvent({
        type: "wsMessage",
        requestId: rid,
        timestamp: Date.now(),
        direction: "send",
        messageType: "text",
        message: str.length <= MAX_BODY_SIZE ? str : `<${str.length} chars>`,
      });

      return method.call(this, text);
    };
  } catch {
  }

  try {
    const method = RealWebSocket.send.overload("okio.ByteString");
    method.implementation = function (this: Java.Wrapper, bytes: Java.Wrapper) {
      const rid = getWsRequestId(this);
      const size = bytes !== null ? bytes.size() : 0;

      emitNetworkEvent({
        type: "wsMessage",
        requestId: rid,
        timestamp: Date.now(),
        direction: "send",
        messageType: "binary",
        dataLength: size,
      });

      return method.call(this, bytes);
    };
  } catch {
  }

  try {
    const method = RealWebSocket.close.overload("int", "java.lang.String");
    method.implementation = function (
      this: Java.Wrapper,
      code: number,
      reason: Java.Wrapper,
    ) {
      const rid = getWsRequestId(this);

      emitNetworkEvent({
        type: "wsClose",
        requestId: rid,
        timestamp: Date.now(),
        code,
        reason: reason !== null ? reason.toString() : "",
        direction: "send",
      });

      return method.call(this, code, reason);
    };
  } catch {
  }

  try {
    const method = RealWebSocket.onReadMessage.overload("java.lang.String");
    method.implementation = function (this: Java.Wrapper, text: Java.Wrapper) {
      const rid = getWsRequestId(this);
      const str = text !== null ? text.toString() : "";

      emitNetworkEvent({
        type: "wsMessage",
        requestId: rid,
        timestamp: Date.now(),
        direction: "receive",
        messageType: "text",
        message: str.length <= MAX_BODY_SIZE ? str : `<${str.length} chars>`,
      });

      return method.call(this, text);
    };
  } catch {
  }

  try {
    const method = RealWebSocket.onReadMessage.overload("okio.ByteString");
    method.implementation = function (this: Java.Wrapper, bytes: Java.Wrapper) {
      const rid = getWsRequestId(this);
      const size = bytes !== null ? bytes.size() : 0;

      emitNetworkEvent({
        type: "wsMessage",
        requestId: rid,
        timestamp: Date.now(),
        direction: "receive",
        messageType: "binary",
        dataLength: size,
      });

      return method.call(this, bytes);
    };
  } catch {
  }

  const checkMethodName = RealWebSocket["checkUpgradeSuccess$okhttp"]
    ? "checkUpgradeSuccess$okhttp"
    : "checkUpgradeSuccess";
  try {
    RealWebSocket[checkMethodName].implementation = function (
      this: Java.Wrapper,
      response: Java.Wrapper,
      exchange: Java.Wrapper,
    ) {
      this[checkMethodName](response, exchange);

      const rid = getWsRequestId(this);
      let url = "";
      let protocol: string | null = null;

      try {
        url = this.originalRequest.value.url().toString();
      } catch { /* ignore */ }

      try {
        protocol = response.header("Sec-WebSocket-Protocol");
      } catch { /* ignore */ }

      emitNetworkEvent({
        type: "wsOpen",
        requestId: rid,
        timestamp: Date.now(),
        url,
        protocol,
      });
    };
  } catch {
  }

  try {
    RealWebSocket.onReadClose.implementation = function (
      this: Java.Wrapper,
      code: number,
      reason: Java.Wrapper,
    ) {
      const rid = getWsRequestId(this);

      emitNetworkEvent({
        type: "wsClose",
        requestId: rid,
        timestamp: Date.now(),
        code,
        reason: reason !== null ? reason.toString() : "",
        direction: "receive",
      });

      return this.onReadClose(code, reason);
    };
  } catch {
  }
}
