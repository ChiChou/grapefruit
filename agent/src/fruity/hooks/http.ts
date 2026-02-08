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
