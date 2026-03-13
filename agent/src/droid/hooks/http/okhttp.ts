import Java from "frida-java-bridge";
import {
  type RequestInfo,
  type ResponseInfo,
  emitNetworkEvent,
  nextRequestId,
  getRequestState,
  removeRequestState,
  tryUse,
  MAX_BODY_SIZE,
} from "./common.js";
import { bt as captureBacktrace } from "@/common/hooks/java.js";
import {
  bodyRegistry,
  byteArrayToBuffer,
  tagStream,
  tagReader,
} from "./body.js";

function extractHeaders(headers: Java.Wrapper): Record<string, string> {
  const result: Record<string, string> = {};
  try {
    const size: number = headers.size();
    for (let i = 0; i < size; i++) {
      result[headers.name(i)] = headers.value(i);
    }
  } catch {
    try {
      const map = headers.toMultimap();
      const iter = map.entrySet().iterator();
      while (iter.hasNext()) {
        const entry = iter.next();
        result[entry.getKey().toString()] = entry.getValue().get(0).toString();
      }
    } catch {
      // give up
    }
  }
  return result;
}

function readRequestBody(body: Java.Wrapper): {
  text?: string;
  length: number;
} {
  if (body === null) return { length: 0 };

  const Buffer = Java.use("okio.Buffer");
  const contentLength: number = body.contentLength();

  if (contentLength > MAX_BODY_SIZE) {
    return { length: contentLength };
  }

  try {
    const buf = Buffer.$new();
    body.writeTo(buf);
    // Java long is signed 64-bit, frida wraps it
    // in Int64 regardless if it overflows JS number or not
    const size = buf.size() as Int64;
    const length = size.toNumber();

    // no need to limit sizeNum
    // at this point the body is already in the memory, so OOM would happen anyway
    const text: string = buf.readUtf8();
    buf.close();

    return { text: text || undefined, length };
  } catch {
    return { length: contentLength > 0 ? contentLength : -1 };
  }
}

function extractRequestInfo(request: Java.Wrapper): RequestInfo {
  const url = request.url().toString();
  const method = request.method();
  const headers = extractHeaders(request.headers());

  const info: RequestInfo = { url, method, headers };

  try {
    const body = request.body();
    if (body !== null) {
      const contentType = body.contentType();
      if (contentType !== null) {
        headers["Content-Type"] = contentType.toString();
      }

      const { text, length } = readRequestBody(body);
      if (text) info.body = text;
      if (length > 0) info.bodyLength = length;
    }
  } catch {
    // no body
  }

  return info;
}

function extractResponseInfo(response: Java.Wrapper): ResponseInfo {
  const info: ResponseInfo = {
    statusCode: response.code(),
    statusMessage: response.message(),
    headers: extractHeaders(response.headers()),
  };

  try {
    info.url = response.request().url().toString();
  } catch {
    /* ignore */
  }

  try {
    const body = response.body();
    if (body !== null) {
      const contentType = body.contentType();
      if (contentType !== null) info.contentType = contentType.toString();
      info.contentLength = body.contentLength();
    }
  } catch {
    /* ignore */
  }

  return info;
}

function hookResponseBodyConsumption(): void {
  const ResponseBody = tryUse("okhttp3.ResponseBody");
  if (!ResponseBody) {
    console.log("ResponseBody not found — body consumption hooks skipped");
    return;
  }

  try {
    const method = ResponseBody.string.overload();
    method.implementation = function (this: Java.Wrapper) {
      const result = method.call(this);
      const jrid = bodyRegistry.get(this);
      if (jrid !== null) {
        const rid = jrid.toString();
        const text = result !== null ? result.toString() : "";
        emitNetworkEvent({
          type: "responseBody",
          requestId: rid,
          timestamp: Date.now(),
          body: text,
          bodyLength: text.length,
        });
      }
      return result;
    };
  } catch {}

  try {
    const method = ResponseBody.bytes.overload();
    method.implementation = function (this: Java.Wrapper) {
      const result = method.call(this);
      const jrid = bodyRegistry.get(this);
      if (jrid !== null) {
        const rid = jrid.toString();
        const buf = byteArrayToBuffer(result);
        if (buf) {
          send(
            {
              subject: "http",
              type: "responseBody",
              requestId: rid,
              timestamp: Date.now(),
              bodyLength: buf.length,
            },
            buf.data,
          );
        }
      }
      return result;
    };
  } catch {}

  try {
    const method = ResponseBody.byteStream.overload();
    method.implementation = function (this: Java.Wrapper) {
      const stream = method.call(this);
      const jrid = bodyRegistry.get(this);
      if (jrid !== null) {
        tagStream(stream, jrid.toString());
      }
      return stream;
    };
  } catch {}

  try {
    const method = ResponseBody.charStream.overload();
    method.implementation = function (this: Java.Wrapper) {
      const reader = method.call(this);
      const jrid = bodyRegistry.get(this);
      if (jrid !== null) {
        tagReader(reader, jrid.toString());
      }
      return reader;
    };
  } catch {}
}

export function hookOkHttp(): void {
  const RealCall =
    tryUse("okhttp3.internal.connection.RealCall") ??
    tryUse("okhttp3.RealCall");

  if (!RealCall) {
    console.log("OkHttp RealCall not found — OkHttp hooks skipped");
    return;
  }

  const methodName = RealCall["getResponseWithInterceptorChain$okhttp"]
    ? "getResponseWithInterceptorChain$okhttp"
    : "getResponseWithInterceptorChain";

  try {
    RealCall[methodName].implementation = function (this: Java.Wrapper) {
      const rid = nextRequestId();
      let requestInfo: RequestInfo;

      try {
        const request = this.getOriginalRequest();
        requestInfo = extractRequestInfo(request!);
      } catch {
        requestInfo = { url: "<unknown>", method: "?", headers: {} };
      }

      const state = getRequestState(rid);
      state.request = requestInfo;

      emitNetworkEvent({
        type: "callStart",
        requestId: rid,
        timestamp: Date.now(),
        request: requestInfo,
        backtrace: captureBacktrace(),
      });

      try {
        const response = this[methodName]();

        const responseInfo = extractResponseInfo(response);
        state.response = responseInfo;

        emitNetworkEvent({
          type: "responseHeaders",
          requestId: rid,
          timestamp: Date.now(),
          response: responseInfo,
        });

        try {
          const body = response.body();
          if (body !== null) {
            bodyRegistry.set(body, Java.use("java.lang.String").$new(rid));
          }
        } catch {
          // body access failed
        }

        emitNetworkEvent({
          type: "callEnd",
          requestId: rid,
          timestamp: Date.now(),
        });

        removeRequestState(rid);
        return response;
      } catch (e) {
        emitNetworkEvent({
          type: "callFailed",
          requestId: rid,
          timestamp: Date.now(),
          error: `${e}`,
        });
        removeRequestState(rid);
        throw e;
      }
    };
  } catch {}

  hookResponseBodyConsumption();
}
