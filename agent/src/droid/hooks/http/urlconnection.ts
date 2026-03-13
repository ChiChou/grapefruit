import Java from "frida-java-bridge";
import {
  type RequestInfo,
  type ResponseInfo,
  emitNetworkEvent,
  nextRequestId,
  getRequestState,
  removeRequestState,
  tryUse,
  identityHash,
} from "./common.js";
import { bt as captureBacktrace } from "@/common/hooks/java.js";
import { tagStream } from "./body.js";

const connRequestIds = new Map<number, string>();
const connStarted = new Set<number>();

function getConnRequestId(conn: Java.Wrapper): string {
  const hash = identityHash(conn);
  let rid = connRequestIds.get(hash);
  if (!rid) {
    rid = nextRequestId();
    connRequestIds.set(hash, rid);
  }
  return rid;
}

function extractRequestInfoFromConn(conn: Java.Wrapper): RequestInfo {
  const url = conn.getURL().toString();
  const method = conn.getRequestMethod();
  const headers: Record<string, string> = {};

  try {
    const headerFields = conn.getRequestProperties();
    const iter = headerFields.entrySet().iterator();
    while (iter.hasNext()) {
      const entry = iter.next();
      const key = entry.getKey();
      if (key !== null) {
        const values = entry.getValue();
        if (values !== null && values.size() > 0) {
          headers[key.toString()] = values.get(0).toString();
        }
      }
    }
  } catch {
    // May fail if already connected
  }

  return { url, method, headers };
}

function extractResponseInfoFromConn(conn: Java.Wrapper): ResponseInfo {
  const info: ResponseInfo = {
    statusCode: 0,
    headers: {},
  };

  try {
    info.statusCode = conn.getResponseCode();
  } catch {
    /* ignore */
  }
  try {
    info.statusMessage = conn.getResponseMessage();
  } catch {
    /* ignore */
  }

  try {
    for (let i = 0; i < 100; i++) {
      const key = conn.getHeaderFieldKey(i);
      if (key === null) {
        if (i > 0) break;
        continue;
      }
      const value = conn.getHeaderField(i);
      if (value !== null) {
        info.headers[key.toString()] = value.toString();
      }
    }
  } catch {
    /* ignore */
  }

  try {
    info.contentType = conn.getContentType();
  } catch {
    /* ignore */
  }
  try {
    info.contentLength = conn.getContentLength();
  } catch {
    /* ignore */
  }
  try {
    info.url = conn.getURL().toString();
  } catch {
    /* ignore */
  }

  return info;
}

function emitCallStartIfNeeded(conn: Java.Wrapper): string {
  const hash = identityHash(conn);
  const rid = getConnRequestId(conn);

  if (!connStarted.has(hash)) {
    connStarted.add(hash);
    const requestInfo = extractRequestInfoFromConn(conn);
    const state = getRequestState(rid);
    state.request = requestInfo;

    emitNetworkEvent({
      type: "callStart",
      requestId: rid,
      timestamp: Date.now(),
      request: requestInfo,
      backtrace: captureBacktrace(),
    });
  }

  return rid;
}

function cleanupConn(conn: Java.Wrapper): void {
  const hash = identityHash(conn);
  const rid = connRequestIds.get(hash);
  if (rid) {
    connRequestIds.delete(hash);
    connStarted.delete(hash);
    removeRequestState(rid);
  }
}

export function hookHttpURLConnection(): void {
  const implClasses = ["com.android.okhttp.internal.huc.HttpURLConnectionImpl"];

  for (const className of implClasses) {
    const Impl = tryUse(className);
    if (!Impl) {
      console.log(`${className} not found, skipping`);
      continue;
    }

    try {
      Impl.getInputStream.implementation = function (this: Java.Wrapper) {
        const rid = emitCallStartIfNeeded(this);

        try {
          const stream = this.getInputStream();

          const responseInfo = extractResponseInfoFromConn(this);
          const state = getRequestState(rid);
          state.response = responseInfo;

          emitNetworkEvent({
            type: "responseHeaders",
            requestId: rid,
            timestamp: Date.now(),
            response: responseInfo,
          });

          tagStream(stream, rid);

          return stream;
        } catch (e: unknown) {
          emitNetworkEvent({
            type: "callFailed",
            requestId: rid,
            timestamp: Date.now(),
            error: `${e}`,
          });
          throw e;
        }
      };
    } catch {}

    try {
      Impl.getOutputStream.implementation = function (this: Java.Wrapper) {
        emitCallStartIfNeeded(this);
        return this.getOutputStream();
      };
    } catch {}

    try {
      Impl.disconnect.implementation = function (this: Java.Wrapper) {
        const hash = identityHash(this);
        const rid = connRequestIds.get(hash);

        this.disconnect();

        if (rid) {
          emitNetworkEvent({
            type: "callEnd",
            requestId: rid,
            timestamp: Date.now(),
          });
          cleanupConn(this);
        }
      };
    } catch {}
  }
}
