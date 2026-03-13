import Java from "frida-java-bridge";
import {
  type RequestInfo,
  type ResponseInfo,
  emitNetworkEvent,
  nextRequestId,
  getRequestState,
  removeRequestState,
  serializeBody,
  tryUse,
} from "./common.js";
import { bt as captureBacktrace } from "@/common/hooks/java.js";
import { byteArrayToBuffer } from "./body.js";

function methodName(method: number): string {
  switch (method) {
    case 0:
      return "GET";
    case 1:
      return "GET";
    case 2:
      return "POST";
    case 3:
      return "PUT";
    case 4:
      return "DELETE";
    case 5:
      return "HEAD";
    case 6:
      return "OPTIONS";
    case 7:
      return "TRACE";
    case 8:
      return "PATCH";
    default:
      return `UNKNOWN(${method})`;
  }
}

function extractVolleyRequestInfo(request: Java.Wrapper): RequestInfo {
  const info: RequestInfo = {
    url: request.getUrl(),
    method: methodName(request.getMethod()),
    headers: {},
  };

  try {
    const headerMap = request.getHeaders();
    const iter = headerMap.entrySet().iterator();
    while (iter.hasNext()) {
      const entry = iter.next();
      info.headers[entry.getKey().toString()] = entry.getValue().toString();
    }
  } catch {
    /* ignore */
  }

  try {
    const body: number[] | null = request.getBody();
    if (body !== null && body.length > 0) {
      info.bodyLength = body.length;
      const text = serializeBody(body as number[]);
      if (text) info.body = text;

      const ct = request.getBodyContentType();
      if (ct) info.headers["Content-Type"] = ct;
    }
  } catch {
    /* ignore */
  }

  return info;
}

function extractVolleyResponseInfo(response: Java.Wrapper): ResponseInfo {
  const info: ResponseInfo = {
    statusCode: response.statusCode.value,
    headers: {},
  };

  try {
    const headerList = response.allHeaders.value;
    if (headerList !== null) {
      const size: number = headerList.size();
      for (let i = 0; i < size; i++) {
        const header = headerList.get(i);
        info.headers[header.getName()] = header.getValue();
      }
    }
  } catch {
    try {
      const headerMap = response.headers.value;
      if (headerMap !== null) {
        const iter = headerMap.entrySet().iterator();
        while (iter.hasNext()) {
          const entry = iter.next();
          info.headers[entry.getKey().toString()] = entry.getValue().toString();
        }
      }
    } catch {
      /* ignore */
    }
  }

  return info;
}

export function hookVolley(): void {
  const BasicNetwork = tryUse("com.android.volley.toolbox.BasicNetwork");
  if (!BasicNetwork) {
    console.log("Volley BasicNetwork not found — Volley hooks skipped");
    return;
  }

  try {
    const overloads = BasicNetwork.performRequest.overloads;
    for (const overload of overloads) {
      overload.implementation = function (
        this: Java.Wrapper,
        request: Java.Wrapper,
        ...rest: Java.Wrapper[]
      ) {
        const rid = nextRequestId();
        const requestInfo = extractVolleyRequestInfo(request);

        if (rest.length > 0 && rest[0] !== null) {
          try {
            const additionalHeaders = rest[0];
            const iter = additionalHeaders.entrySet().iterator();
            while (iter.hasNext()) {
              const entry = iter.next();
              requestInfo.headers[entry.getKey().toString()] = entry
                .getValue()
                .toString();
            }
          } catch {
            /* ignore */
          }
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
          const response = overload.call(this, request, ...rest);

          const responseInfo = extractVolleyResponseInfo(response);
          state.response = responseInfo;

          emitNetworkEvent({
            type: "responseHeaders",
            requestId: rid,
            timestamp: Date.now(),
            response: responseInfo,
          });

          try {
            const data = response.data.value;
            if (data !== null) {
              const buf = byteArrayToBuffer(data);
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
          } catch {
            /* ignore */
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
    }
  } catch {}

  const RequestQueue = tryUse("com.android.volley.RequestQueue");
  if (RequestQueue) {
    try {
      RequestQueue.add.implementation = function (
        this: Java.Wrapper,
        request: Java.Wrapper,
      ) {
        try {
          console.log(
            `Volley queued: ${methodName(request.getMethod())} ${request.getUrl()}`,
          );
        } catch {
          /* ignore */
        }
        return this.add(request);
      };
    } catch {}
  }
}
