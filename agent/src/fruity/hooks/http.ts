import ObjC from "frida-objc-bridge";
import { BaseMessage, bt } from "./context.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "http";

  // Request metadata
  method?: string; // GET, POST, PUT, DELETE, etc.
  url?: string; // Full URL string
  requestId?: string; // Unique ID to correlate request/response

  // Phase indicator
  phase: "request" | "response" | "error";

  // Request details
  requestHeaders?: Record<string, string>;
  requestBodySize?: number;
  hasRequestBody?: boolean;

  // Response details
  statusCode?: number;
  responseHeaders?: Record<string, string>;
  responseBodySize?: number;
  hasResponseBody?: boolean;
  mimeType?: string;

  // Timing
  timestamp?: number;
  latency?: number; // Response time in milliseconds

  // Error handling
  error?: string;
}

// Global state for request timing
const requestTimestamps = new Map<string, number>();

// Extract URL from NSURLRequest
function extractURL(request: ObjC.Object): string {
  try {
    const url = request.URL();
    return url && !url.isNull() ? url.absoluteString().toString() : "";
  } catch (e) {
    return "";
  }
}

// Extract HTTP method from NSURLRequest
function extractMethod(request: ObjC.Object): string {
  try {
    const method = request.HTTPMethod();
    return method && !method.isNull() ? method.toString() : "GET";
  } catch (e) {
    return "GET";
  }
}

// Extract headers from NSURLRequest
function extractRequestHeaders(
  request: ObjC.Object,
): Record<string, string> {
  const headers: Record<string, string> = {};
  try {
    const allHeaders = request.allHTTPHeaderFields();

    if (allHeaders && !allHeaders.isNull()) {
      const keys = allHeaders.allKeys();
      const count = keys.count();

      for (let i = 0; i < count; i++) {
        const key = keys.objectAtIndex_(i).toString();
        const value = allHeaders.objectForKey_(key).toString();
        headers[key] = value;
      }
    }
  } catch (e) {
    // Ignore errors
  }

  return headers;
}

// Extract body from NSURLRequest
function extractRequestBody(request: ObjC.Object): {
  data: ArrayBuffer | null;
  size: number;
} {
  try {
    const body = request.HTTPBody();

    if (body && !body.isNull()) {
      const size = body.length();
      // Only capture body if < 1MB to avoid performance issues
      if (size <= 1024 * 1024) {
        return {
          data: body.bytes().readByteArray(size),
          size: size,
        };
      }
      return { data: null, size: size };
    }
  } catch (e) {
    // Ignore errors
  }

  return { data: null, size: 0 };
}

// Extract response info from NSHTTPURLResponse
function extractResponseInfo(response: ObjC.Object): {
  statusCode: number;
  headers: Record<string, string>;
  mimeType: string;
} {
  const result = {
    statusCode: 0,
    headers: {} as Record<string, string>,
    mimeType: "",
  };

  try {
    result.statusCode = response.statusCode();

    const mimeType = response.MIMEType();
    if (mimeType && !mimeType.isNull()) {
      result.mimeType = mimeType.toString();
    }

    const allHeaders = response.allHeaderFields();
    if (allHeaders && !allHeaders.isNull()) {
      const keys = allHeaders.allKeys();
      const count = keys.count();

      for (let i = 0; i < count; i++) {
        const key = keys.objectAtIndex_(i).toString();
        const value = allHeaders.objectForKey_(key).toString();
        result.headers[key] = value;
      }
    }
  } catch (e) {
    // Ignore errors
  }

  return result;
}

// Generate unique request ID from task handle
function generateRequestId(task: ObjC.Object): string {
  return task.handle.toString();
}

// Quote string for display
function q(s: string | null | undefined): string {
  if (!s) return '""';
  if (s.length > 200) return `"${s.substring(0, 197)}..."`;
  return `"${s}"`;
}

// Cleanup old request timestamps (prevent memory leaks)
setInterval(() => {
  const now = Date.now();
  const maxAge = 60000; // 60 seconds
  for (const [id, timestamp] of requestTimestamps.entries()) {
    if (now - timestamp > maxAge) {
      requestTimestamps.delete(id);
    }
  }
}, 30000);

/**
 * Hook NSURLSession data task creation methods
 */
export function urlSessionDataTasks() {
  if (!ObjC.available) return [];

  const NSURLSession = ObjC.classes.NSURLSession;
  if (!NSURLSession) return [];

  const hooks: InvocationListener[] = [];

  // Hook: -[NSURLSession dataTaskWithRequest:]
  const dataTaskWithRequest = NSURLSession["- dataTaskWithRequest:"];
  if (dataTaskWithRequest) {
    hooks.push(
      Interceptor.attach(dataTaskWithRequest.implementation, {
        onEnter(args) {
          this.request = new ObjC.Object(args[2]);
        },
        onLeave(retval) {
          if (retval.isNull()) return;

          try {
            const task = new ObjC.Object(retval);
            const request = this.request;
            const requestId = generateRequestId(task);
            const url = extractURL(request);
            const method = extractMethod(request);
            const headers = extractRequestHeaders(request);
            const { data: bodyData, size: bodySize } =
              extractRequestBody(request);

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "-[NSURLSession dataTaskWithRequest:]",
              dir: "leave",
              line: `${method} ${q(url)}`,
              phase: "request",
              method,
              url,
              requestId,
              requestHeaders: headers,
              requestBodySize: bodySize,
              hasRequestBody: bodySize > 0,
              timestamp: Date.now(),
              backtrace: bt(this.context),
            };

            send(detail, bodyData);
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  // Hook: -[NSURLSession dataTaskWithRequest:completionHandler:]
  const dataTaskWithRequestCompletion =
    NSURLSession["- dataTaskWithRequest:completionHandler:"];
  if (dataTaskWithRequestCompletion) {
    hooks.push(
      Interceptor.attach(dataTaskWithRequestCompletion.implementation, {
        onEnter(args) {
          this.request = new ObjC.Object(args[2]);
          this.taskPtr = null;

          try {
            const originalHandler = new ObjC.Block(args[3]);
            const request = this.request;

            const wrappedHandler = new ObjC.Block({
              retType: "void",
              argTypes: ["object", "object", "object"],
              implementation: (
                data: NativePointer,
                response: NativePointer,
                error: NativePointer,
              ) => {
                // Call original handler first
                originalHandler.implementation(data, response, error);

                // Capture response
                try {
                  const requestId = this.taskPtr
                    ? this.taskPtr.toString()
                    : "unknown";
                  const startTime = requestTimestamps.get(requestId);
                  const latency = startTime ? Date.now() - startTime : undefined;
                  const url = extractURL(request);
                  const method = extractMethod(request);

                  if (!error.isNull()) {
                    // Error case
                    const errObj = new ObjC.Object(error);
                    const errMsg =
                      errObj.localizedDescription()?.toString() ||
                      "Unknown error";

                    send({
                      subject: "hook",
                      category: "http",
                      symbol: "completionHandler",
                      dir: "leave",
                      line: `${method} ${q(url)} - Error: ${errMsg}`,
                      phase: "error",
                      method,
                      url,
                      requestId,
                      error: errMsg,
                      latency,
                    } as Message);
                  } else if (!response.isNull()) {
                    // Success case
                    const respObj = new ObjC.Object(response);
                    const { statusCode, headers, mimeType } =
                      extractResponseInfo(respObj);

                    let responseBodySize = 0;
                    let responseData: ArrayBuffer | null = null;

                    if (!data.isNull()) {
                      const dataObj = new ObjC.Object(data);
                      responseBodySize = dataObj.length();

                      if (responseBodySize <= 1024 * 1024) {
                        responseData = dataObj
                          .bytes()
                          .readByteArray(responseBodySize);
                      }
                    }

                    send(
                      {
                        subject: "hook",
                        category: "http",
                        symbol: "completionHandler",
                        dir: "leave",
                        line: `${method} ${q(url)} -> ${statusCode}`,
                        phase: "response",
                        method,
                        url,
                        requestId,
                        statusCode,
                        responseHeaders: headers,
                        responseBodySize,
                        hasResponseBody: responseBodySize > 0,
                        mimeType,
                        latency,
                      } as Message,
                      responseData,
                    );
                  }

                  // Clean up
                  if (requestId !== "unknown") {
                    requestTimestamps.delete(requestId);
                  }
                } catch (e) {
                  // Ignore errors in completion handler
                }
              },
            });

            // Replace the completion handler
            args[3] = wrappedHandler.handle;
          } catch (e) {
            // Ignore errors
          }
        },
        onLeave(retval) {
          if (retval.isNull()) return;

          try {
            const task = new ObjC.Object(retval);
            const request = this.request;
            const requestId = generateRequestId(task);
            this.taskPtr = task.handle;

            const url = extractURL(request);
            const method = extractMethod(request);
            const headers = extractRequestHeaders(request);
            const { data: bodyData, size: bodySize } =
              extractRequestBody(request);

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "-[NSURLSession dataTaskWithRequest:completionHandler:]",
              dir: "leave",
              line: `${method} ${q(url)}`,
              phase: "request",
              method,
              url,
              requestId,
              requestHeaders: headers,
              requestBodySize: bodySize,
              hasRequestBody: bodySize > 0,
              timestamp: Date.now(),
              backtrace: bt(this.context),
            };

            send(detail, bodyData);
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  // Hook: -[NSURLSession dataTaskWithURL:]
  const dataTaskWithURL = NSURLSession["- dataTaskWithURL:"];
  if (dataTaskWithURL) {
    hooks.push(
      Interceptor.attach(dataTaskWithURL.implementation, {
        onEnter(args) {
          this.url = new ObjC.Object(args[2]);
        },
        onLeave(retval) {
          if (retval.isNull()) return;

          try {
            const task = new ObjC.Object(retval);
            const requestId = generateRequestId(task);
            const url = this.url.absoluteString().toString();

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "-[NSURLSession dataTaskWithURL:]",
              dir: "leave",
              line: `GET ${q(url)}`,
              phase: "request",
              method: "GET",
              url,
              requestId,
              requestHeaders: {},
              requestBodySize: 0,
              hasRequestBody: false,
              timestamp: Date.now(),
              backtrace: bt(this.context),
            };

            send(detail);
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  // Hook: -[NSURLSession dataTaskWithURL:completionHandler:]
  const dataTaskWithURLCompletion =
    NSURLSession["- dataTaskWithURL:completionHandler:"];
  if (dataTaskWithURLCompletion) {
    hooks.push(
      Interceptor.attach(dataTaskWithURLCompletion.implementation, {
        onEnter(args) {
          this.url = new ObjC.Object(args[2]);
          this.taskPtr = null;

          try {
            const originalHandler = new ObjC.Block(args[3]);
            const url = this.url.absoluteString().toString();

            const wrappedHandler = new ObjC.Block({
              retType: "void",
              argTypes: ["object", "object", "object"],
              implementation: (
                data: NativePointer,
                response: NativePointer,
                error: NativePointer,
              ) => {
                // Call original handler first
                originalHandler.implementation(data, response, error);

                // Capture response
                try {
                  const requestId = this.taskPtr
                    ? this.taskPtr.toString()
                    : "unknown";
                  const startTime = requestTimestamps.get(requestId);
                  const latency = startTime ? Date.now() - startTime : undefined;

                  if (!error.isNull()) {
                    // Error case
                    const errObj = new ObjC.Object(error);
                    const errMsg =
                      errObj.localizedDescription()?.toString() ||
                      "Unknown error";

                    send({
                      subject: "hook",
                      category: "http",
                      symbol: "completionHandler",
                      dir: "leave",
                      line: `GET ${q(url)} - Error: ${errMsg}`,
                      phase: "error",
                      method: "GET",
                      url,
                      requestId,
                      error: errMsg,
                      latency,
                    } as Message);
                  } else if (!response.isNull()) {
                    // Success case
                    const respObj = new ObjC.Object(response);
                    const { statusCode, headers, mimeType } =
                      extractResponseInfo(respObj);

                    let responseBodySize = 0;
                    let responseData: ArrayBuffer | null = null;

                    if (!data.isNull()) {
                      const dataObj = new ObjC.Object(data);
                      responseBodySize = dataObj.length();

                      if (responseBodySize <= 1024 * 1024) {
                        responseData = dataObj
                          .bytes()
                          .readByteArray(responseBodySize);
                      }
                    }

                    send(
                      {
                        subject: "hook",
                        category: "http",
                        symbol: "completionHandler",
                        dir: "leave",
                        line: `GET ${q(url)} -> ${statusCode}`,
                        phase: "response",
                        method: "GET",
                        url,
                        requestId,
                        statusCode,
                        responseHeaders: headers,
                        responseBodySize,
                        hasResponseBody: responseBodySize > 0,
                        mimeType,
                        latency,
                      } as Message,
                      responseData,
                    );
                  }

                  // Clean up
                  if (requestId !== "unknown") {
                    requestTimestamps.delete(requestId);
                  }
                } catch (e) {
                  // Ignore errors in completion handler
                }
              },
            });

            // Replace the completion handler
            args[3] = wrappedHandler.handle;
          } catch (e) {
            // Ignore errors
          }
        },
        onLeave(retval) {
          if (retval.isNull()) return;

          try {
            const task = new ObjC.Object(retval);
            const requestId = generateRequestId(task);
            this.taskPtr = task.handle;
            const url = this.url.absoluteString().toString();

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "-[NSURLSession dataTaskWithURL:completionHandler:]",
              dir: "leave",
              line: `GET ${q(url)}`,
              phase: "request",
              method: "GET",
              url,
              requestId,
              requestHeaders: {},
              requestBodySize: 0,
              hasRequestBody: false,
              timestamp: Date.now(),
              backtrace: bt(this.context),
            };

            send(detail);
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  return hooks;
}

/**
 * Hook NSURLSession upload task creation methods
 */
export function urlSessionUploadTasks() {
  if (!ObjC.available) return [];

  const NSURLSession = ObjC.classes.NSURLSession;
  if (!NSURLSession) return [];

  const hooks: InvocationListener[] = [];

  // Hook: -[NSURLSession uploadTaskWithRequest:fromData:]
  const uploadTaskWithRequestFromData =
    NSURLSession["- uploadTaskWithRequest:fromData:"];
  if (uploadTaskWithRequestFromData) {
    hooks.push(
      Interceptor.attach(uploadTaskWithRequestFromData.implementation, {
        onEnter(args) {
          this.request = new ObjC.Object(args[2]);
          this.uploadData = new ObjC.Object(args[3]);
        },
        onLeave(retval) {
          if (retval.isNull()) return;

          try {
            const task = new ObjC.Object(retval);
            const request = this.request;
            const uploadData = this.uploadData;
            const requestId = generateRequestId(task);
            const url = extractURL(request);
            const method = extractMethod(request);
            const headers = extractRequestHeaders(request);

            let uploadSize = 0;
            let uploadBuffer: ArrayBuffer | null = null;

            if (uploadData && !uploadData.isNull()) {
              uploadSize = uploadData.length();
              if (uploadSize <= 1024 * 1024) {
                uploadBuffer = uploadData.bytes().readByteArray(uploadSize);
              }
            }

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "-[NSURLSession uploadTaskWithRequest:fromData:]",
              dir: "leave",
              line: `${method} ${q(url)} (upload ${uploadSize} bytes)`,
              phase: "request",
              method,
              url,
              requestId,
              requestHeaders: headers,
              requestBodySize: uploadSize,
              hasRequestBody: uploadSize > 0,
              timestamp: Date.now(),
              backtrace: bt(this.context),
            };

            send(detail, uploadBuffer);
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  return hooks;
}

/**
 * Hook NSURLSession download task creation methods
 */
export function urlSessionDownloadTasks() {
  if (!ObjC.available) return [];

  const NSURLSession = ObjC.classes.NSURLSession;
  if (!NSURLSession) return [];

  const hooks: InvocationListener[] = [];

  // Hook: -[NSURLSession downloadTaskWithRequest:]
  const downloadTaskWithRequest =
    NSURLSession["- downloadTaskWithRequest:"];
  if (downloadTaskWithRequest) {
    hooks.push(
      Interceptor.attach(downloadTaskWithRequest.implementation, {
        onEnter(args) {
          this.request = new ObjC.Object(args[2]);
        },
        onLeave(retval) {
          if (retval.isNull()) return;

          try {
            const task = new ObjC.Object(retval);
            const request = this.request;
            const requestId = generateRequestId(task);
            const url = extractURL(request);
            const method = extractMethod(request);
            const headers = extractRequestHeaders(request);

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "-[NSURLSession downloadTaskWithRequest:]",
              dir: "leave",
              line: `${method} ${q(url)} (download)`,
              phase: "request",
              method,
              url,
              requestId,
              requestHeaders: headers,
              requestBodySize: 0,
              hasRequestBody: false,
              timestamp: Date.now(),
              backtrace: bt(this.context),
            };

            send(detail);
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  return hooks;
}

/**
 * Hook NSURLSessionTask resume to track when requests actually start
 */
export function urlSessionTaskResume() {
  if (!ObjC.available) return [];

  const NSURLSessionTask = ObjC.classes.NSURLSessionTask;
  if (!NSURLSessionTask) return [];

  const hooks: InvocationListener[] = [];

  // Hook: -[NSURLSessionTask resume]
  const resume = NSURLSessionTask["- resume"];
  if (resume) {
    hooks.push(
      Interceptor.attach(resume.implementation, {
        onEnter(args) {
          try {
            const task = new ObjC.Object(args[0]);
            const requestId = generateRequestId(task);

            // Store timestamp for latency calculation
            requestTimestamps.set(requestId, Date.now());
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  return hooks;
}

/**
 * Hook legacy NSURLConnection synchronous requests
 */
export function urlConnection() {
  if (!ObjC.available) return [];

  const NSURLConnection = ObjC.classes.NSURLConnection;
  if (!NSURLConnection) return [];

  const hooks: InvocationListener[] = [];

  // Hook: +[NSURLConnection sendSynchronousRequest:returningResponse:error:]
  const sendSync =
    NSURLConnection["+ sendSynchronousRequest:returningResponse:error:"];
  if (sendSync) {
    hooks.push(
      Interceptor.attach(sendSync.implementation, {
        onEnter(args) {
          try {
            this.request = new ObjC.Object(args[2]);
            this.responsePtr = args[3];
            this.startTime = Date.now();

            const request = this.request;
            const url = extractURL(request);
            const method = extractMethod(request);
            const headers = extractRequestHeaders(request);
            const { data: bodyData, size: bodySize } =
              extractRequestBody(request);

            const detail: Message = {
              subject: "hook",
              category: "http",
              symbol: "+[NSURLConnection sendSynchronousRequest:returningResponse:error:]",
              dir: "enter",
              line: `${method} ${q(url)} (sync)`,
              phase: "request",
              method,
              url,
              requestHeaders: headers,
              requestBodySize: bodySize,
              hasRequestBody: bodySize > 0,
              timestamp: this.startTime,
              backtrace: bt(this.context),
            };

            send(detail, bodyData);
          } catch (e) {
            // Ignore errors
          }
        },
        onLeave(retval) {
          try {
            const latency = Date.now() - this.startTime;
            const url = extractURL(this.request);
            const method = extractMethod(this.request);

            // Check if response pointer is valid
            if (this.responsePtr && !this.responsePtr.isNull()) {
              const responseObj = this.responsePtr.readPointer();
              if (!responseObj.isNull()) {
                const response = new ObjC.Object(responseObj);
                const { statusCode, headers, mimeType } =
                  extractResponseInfo(response);

                let responseBodySize = 0;
                let responseData: ArrayBuffer | null = null;

                if (!retval.isNull()) {
                  const dataObj = new ObjC.Object(retval);
                  responseBodySize = dataObj.length();

                  if (responseBodySize <= 1024 * 1024) {
                    responseData = dataObj.bytes().readByteArray(responseBodySize);
                  }
                }

                send(
                  {
                    subject: "hook",
                    category: "http",
                    symbol: "+[NSURLConnection sendSynchronousRequest:returningResponse:error:]",
                    dir: "leave",
                    line: `${method} ${q(url)} -> ${statusCode} (sync)`,
                    phase: "response",
                    method,
                    url,
                    statusCode,
                    responseHeaders: headers,
                    responseBodySize,
                    hasResponseBody: responseBodySize > 0,
                    mimeType,
                    latency,
                  } as Message,
                  responseData,
                );
              }
            }
          } catch (e) {
            // Ignore errors
          }
        },
      }),
    );
  }

  return hooks;
}
