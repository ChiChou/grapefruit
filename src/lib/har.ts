import fs from "node:fs";
import type { CapturedRequest } from "./store/nsurl.ts";

interface HARNameValue {
  name: string;
  value: string;
}

interface HAREntry {
  startedDateTime: string;
  time: number;
  request: {
    method: string;
    url: string;
    httpVersion: string;
    cookies: HARNameValue[];
    headers: HARNameValue[];
    queryString: HARNameValue[];
    postData?: { mimeType: string; text: string };
    headersSize: number;
    bodySize: number;
  };
  response: {
    status: number;
    statusText: string;
    httpVersion: string;
    cookies: HARNameValue[];
    headers: HARNameValue[];
    content: {
      size: number;
      mimeType: string;
      text?: string;
      encoding?: string;
    };
    redirectURL: string;
    headersSize: number;
    bodySize: number;
  };
  cache: Record<string, never>;
  timings: { send: number; wait: number; receive: number };
}

function headersToList(
  headers?: Record<string, string>,
): HARNameValue[] {
  if (!headers) return [];
  return Object.entries(headers).map(([name, value]) => ({ name, value }));
}

function parseQueryString(url: string): HARNameValue[] {
  try {
    const parsed = new URL(url);
    return Array.from(parsed.searchParams.entries()).map(([name, value]) => ({
      name,
      value,
    }));
  } catch {
    return [];
  }
}

const TEXT_MIME_PREFIXES = [
  "text/",
  "application/json",
  "application/xml",
  "application/javascript",
  "application/x-javascript",
  "application/ecmascript",
  "application/x-www-form-urlencoded",
  "application/xhtml+xml",
  "application/soap+xml",
  "application/graphql",
  "image/svg+xml",
];

function isTextMime(mimeType: string): boolean {
  const lower = mimeType.toLowerCase();
  return TEXT_MIME_PREFIXES.some((p) => lower.startsWith(p));
}

function readAttachment(
  path: string | null | undefined,
  mimeType: string,
): { text?: string; encoding?: string } {
  if (!path) return {};
  try {
    const buf = fs.readFileSync(path);
    if (buf.length === 0) return {};
    if (isTextMime(mimeType)) {
      return { text: buf.toString("utf-8") };
    }
    return { text: buf.toString("base64"), encoding: "base64" };
  } catch {
    return {};
  }
}

function statusText(code: number): string {
  const map: Record<number, string> = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
  };
  return map[code] ?? "";
}

export function toHAR(requests: CapturedRequest[]) {
  const entries: HAREntry[] = requests.map((req) => {
    const mime = req.mimeType ?? "";
    const body = readAttachment(req.attachment, mime);
    const requestBodySize = req.requestBody
      ? Buffer.byteLength(req.requestBody, "utf-8")
      : 0;

    return {
      startedDateTime: new Date(req.startTime).toISOString(),
      time: req.duration ?? 0,
      request: {
        method: req.method || "GET",
        url: req.url,
        httpVersion: "HTTP/1.1",
        cookies: [],
        headers: headersToList(req.requestHeaders),
        queryString: parseQueryString(req.url),
        ...(req.requestBody
          ? {
              postData: {
                mimeType:
                  req.requestHeaders?.["Content-Type"] ??
                  req.requestHeaders?.["content-type"] ??
                  "application/octet-stream",
                text: req.requestBody,
              },
            }
          : {}),
        headersSize: -1,
        bodySize: requestBodySize,
      },
      response: {
        status: req.statusCode ?? 0,
        statusText: statusText(req.statusCode ?? 0),
        httpVersion: "HTTP/1.1",
        cookies: [],
        headers: headersToList(req.responseHeaders),
        content: {
          size: req.size,
          mimeType: mime,
          ...body,
        },
        redirectURL: "",
        headersSize: -1,
        bodySize: req.size,
      },
      cache: {},
      timings: {
        send: 0,
        wait: req.duration ?? 0,
        receive: 0,
      },
    };
  });

  return {
    log: {
      version: "1.2",
      creator: { name: "igf", version: "1.0" },
      entries,
    },
  };
}
