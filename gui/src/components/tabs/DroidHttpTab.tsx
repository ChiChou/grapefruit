import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import {
  Trash2,
  ArrowUp,
  ArrowDown,
  Download,
  Copy,
  Check,
  Loader2,
  Play,
  Square,
  ChevronsDown,
} from "lucide-react";

import {
  formats,
  generate,
  type FormatId,
  type RequestInfo,
} from "@/lib/codegen/nsurl";

import { Button, buttonVariants } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { HttpResponseBodyView } from "@/components/shared/HttpResponseBodyView";
import { useSession, Status } from "@/context/SessionContext";

const TAP_ID = "http";
import { useDroidQuery } from "@/lib/queries";
import type { HttpEvent } from "@/lib/rpc";

interface WebSocketMessage {
  direction: "send" | "receive";
  messageType: "data" | "string";
  message?: string;
  dataLength?: number;
  error?: string;
  timestamp: number;
}

interface CapturedRequest {
  id: string;
  method: string;
  url: string;
  statusCode?: number;
  mimeType?: string;
  size: bigint;
  startTime: number;
  endTime?: number;
  duration?: number;
  requestHeaders: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBody?: string;
  error?: string;
  mechanism?: string;
  backtrace?: string[];
  isWebSocket?: boolean;
  wsMessages?: WebSocketMessage[];
  attachment?: string | null;
}

function formatSize(bytes: bigint | number): string {
  const n = Number(bytes);
  if (!n || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(
    Math.floor(Math.log(n) / Math.log(1024)),
    units.length - 1,
  );
  return `${(n / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

function formatDuration(ms: number | undefined): string {
  if (ms === undefined) return "-";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

function statusColor(code: number | undefined): string {
  if (!code) return "";
  if (code >= 200 && code < 300) return "text-green-600";
  if (code >= 300 && code < 400) return "text-yellow-600";
  if (code >= 400) return "text-red-600";
  return "";
}

function parseUrl(raw: string): {
  pathname: string;
  host: string;
  params: [string, string][];
} {
  try {
    const u = new URL(raw);
    return {
      pathname: u.pathname,
      host: u.host,
      params: [...u.searchParams.entries()],
    };
  } catch {
    return { pathname: raw, host: "", params: [] };
  }
}

function parseCookieValue(value: string): { key: string; value: string }[] {
  return value.split(/;\s*/).map((pair) => {
    const eq = pair.indexOf("=");
    if (eq === -1) return { key: pair.trim(), value: "" };
    return { key: pair.substring(0, eq).trim(), value: pair.substring(eq + 1) };
  });
}

function handleEventPure(map: Map<string, CapturedRequest>, event: HttpEvent) {
  const { type: eventType, requestId } = event;

  function getOrCreate(id: string): CapturedRequest {
    let entry = map.get(id);
    if (!entry) {
      entry = {
        id,
        method: "",
        url: "",
        requestHeaders: {},
        size: 0n,
        startTime: event.timestamp,
      };
      map.set(id, entry);
    }
    return entry;
  }

  switch (eventType) {
    case "callStart": {
      const entry = getOrCreate(requestId);
      entry.method = event.request.method;
      entry.url = event.request.url;
      entry.requestHeaders = event.request.headers || {};
      entry.requestBody = event.request.body;
      if (event.backtrace) entry.backtrace = event.backtrace;
      break;
    }
    case "responseHeaders": {
      const entry = getOrCreate(requestId);
      entry.statusCode = event.response.statusCode;
      entry.mimeType = event.response.contentType;
      entry.responseHeaders = event.response.headers;
      if (event.response.url && !entry.url) entry.url = event.response.url;
      break;
    }
    case "responseBody": {
      const entry = getOrCreate(requestId);
      try {
        entry.size += BigInt(event.bodyLength ?? 0);
      } catch {
        /* ignore */
      }
      if (event.hasBody) {
        entry.attachment = entry.attachment ?? requestId;
      }
      break;
    }
    case "responseBodyChunk": {
      const entry = getOrCreate(requestId);
      try {
        entry.size += BigInt(event.bytesRead ?? event.charsRead ?? 0);
      } catch {
        /* ignore */
      }
      break;
    }
    case "responseBodyEnd": {
      const entry = getOrCreate(requestId);
      if (!entry.endTime) {
        entry.endTime = event.timestamp;
        entry.duration = event.timestamp - entry.startTime;
      }
      if (event.hasBody) {
        entry.attachment = entry.attachment ?? requestId;
      }
      break;
    }
    case "callEnd": {
      const entry = getOrCreate(requestId);
      entry.endTime = event.timestamp;
      entry.duration = event.timestamp - entry.startTime;
      if (event.hasBody) {
        entry.attachment = entry.attachment ?? requestId;
      }
      break;
    }
    case "callFailed": {
      const entry = getOrCreate(requestId);
      entry.error = event.error;
      entry.endTime = event.timestamp;
      entry.duration = event.timestamp - entry.startTime;
      break;
    }
    case "wsOpen": {
      const entry = getOrCreate(requestId);
      entry.isWebSocket = true;
      if (!entry.method) entry.method = "WS";
      if (event.url) entry.url = event.url;
      break;
    }
    case "wsMessage": {
      const entry = getOrCreate(requestId);
      entry.isWebSocket = true;
      if (!entry.method) entry.method = "WS";
      if (!entry.wsMessages) entry.wsMessages = [];
      entry.wsMessages.push({
        direction: event.direction ?? "receive",
        messageType: event.messageType === "text" ? "string" : "data",
        message: event.message,
        dataLength: event.dataLength != null
          ? Number(event.dataLength)
          : undefined,
        timestamp: event.timestamp,
      });
      break;
    }
    case "wsClose": {
      const entry = getOrCreate(requestId);
      entry.isWebSocket = true;
      if (!entry.wsMessages) entry.wsMessages = [];
      entry.wsMessages.push({
        direction: event.direction ?? "receive",
        messageType: "string",
        message: `Close: code=${event.code} reason=${event.reason ?? ""}`,
        timestamp: event.timestamp,
      });
      break;
    }
    case "wsFailure": {
      const entry = getOrCreate(requestId);
      entry.error = event.error;
      break;
    }
  }
}

function HeadersView({
  headers,
}: {
  headers: Record<string, string> | undefined;
}) {
  if (!headers || Object.keys(headers).length === 0) return <span>(none)</span>;

  const entries = Object.entries(headers);
  return (
    <div className="space-y-0.5">
      {entries.map(([k, v], i) => {
        const lower = k.toLowerCase();
        const isCookie = lower === "cookie" || lower === "set-cookie";
        return (
          <div key={i} className="text-xs font-mono break-all">
            <span className="text-blue-500 dark:text-blue-400">{k}</span>
            <span className="text-muted-foreground">: </span>
            {isCookie ? (
              <span>
                {parseCookieValue(v).map((c, j) => (
                  <span key={j}>
                    {j > 0 && <span className="text-muted-foreground">; </span>}
                    <span className="text-blue-500 dark:text-blue-400">
                      {c.key}
                    </span>
                    {c.value && (
                      <>
                        <span className="text-muted-foreground">=</span>
                        <span className="text-emerald-600 dark:text-emerald-400">
                          {c.value}
                        </span>
                      </>
                    )}
                  </span>
                ))}
              </span>
            ) : (
              <span className="text-foreground">{v}</span>
            )}
          </div>
        );
      })}
    </div>
  );
}

function CopyAsButtons({ request }: { request: RequestInfo }) {
  const [copied, setCopied] = useState<FormatId | null>(null);

  const handleCopy = useCallback(
    (id: FormatId) => {
      navigator.clipboard.writeText(generate(id, request));
      setCopied(id);
      setTimeout(() => setCopied(null), 1500);
    },
    [request],
  );

  return (
    <div className="flex items-center gap-2 mt-2">
      <span className="text-xs text-muted-foreground">Copy as</span>
      {formats.map((f) => (
        <button
          key={f.id}
          onClick={() => handleCopy(f.id)}
          className="inline-flex items-center gap-1.5 h-7 px-2.5 text-xs border rounded-md border-input text-foreground hover:bg-accent transition cursor-pointer"
        >
          {copied === f.id ? (
            <Check className="w-3.5 h-3.5 text-green-500" />
          ) : (
            <Copy className="w-3.5 h-3.5" />
          )}
          {f.label}
        </button>
      ))}
    </div>
  );
}

export function DroidHttpTab() {
  const { socket, status, device, identifier, droid } = useSession();

  const [requests, setRequests] = useState<Map<string, CapturedRequest>>(
    () => new Map(),
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const tableEndRef = useRef<HTMLDivElement>(null);
  const pendingRef = useRef<HttpEvent[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [hookEnabled, setHookEnabled] = useState<boolean | null>(null);
  const [hookLoading, setHookLoading] = useState(false);

  const { data: initialActive } = useDroidQuery<boolean>(
    ["httpActive", device ?? "", identifier ?? ""],
    (api) => api.pins.active(TAP_ID),
  );

  useEffect(() => {
    if (initialActive !== undefined && hookEnabled === null) {
      setHookEnabled(initialActive);
    }
  }, [initialActive, hookEnabled]);

  const handleToggleHook = async (enabled: boolean) => {
    if (!droid) return;
    setHookLoading(true);
    try {
      if (enabled) {
        await droid.pins.start(TAP_ID);
      } else {
        await droid.pins.stop(TAP_ID);
      }
      setHookEnabled(enabled);
    } catch (error) {
      console.error(
        `Failed to ${enabled ? "start" : "stop"} HTTP hook:`,
        error,
      );
    } finally {
      setHookLoading(false);
    }
  };

  const flushPending = useCallback(() => {
    timerRef.current = null;
    if (pendingRef.current.length === 0) return;

    const incoming = pendingRef.current;
    pendingRef.current = [];

    setRequests((prev) => {
      const next = new Map(prev);
      for (const event of incoming) {
        handleEventPure(next, event);
      }
      return next;
    });
  }, []);

  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onHttp = (event: HttpEvent) => {
      pendingRef.current.push(event);
      if (!timerRef.current) {
        timerRef.current = setTimeout(flushPending, 100);
      }
    };

    socket.on("droidHttp", onHttp);
    return () => {
      socket.off("droidHttp", onHttp);
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [socket, status, flushPending]);

  const { data: httpHistory } = useQuery<{
    requests: (CapturedRequest & { size: string | number })[];
  }>({
    queryKey: ["httpHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(
        `/api/history/http/${device}/${identifier}?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load HTTP history");
      return res.json();
    },
    enabled: !!device && !!identifier,
    staleTime: Infinity,
    gcTime: 0,
  });

  useEffect(() => {
    if (!httpHistory?.requests?.length) return;
    setRequests(() => {
      const map = new Map<string, CapturedRequest>();
      for (const req of [...httpHistory.requests].reverse()) {
        map.set(req.id, { ...req, size: BigInt(req.size || 0) });
      }
      return map;
    });
  }, [httpHistory]);

  const clearHttpMutation = useMutation({
    mutationFn: async () => {
      if (!device || !identifier) return;
      const res = await fetch(`/api/history/http/${device}/${identifier}`, {
        method: "DELETE",
      });
      if (!res.ok)
        throw new Error("Failed to clear HTTP records from database");
    },
  });

  const handleClear = () => {
    setRequests(new Map());
    setSelectedId(null);
    clearHttpMutation.mutate();
  };

  const requestList = Array.from(requests.values());
  const selectedRequest = selectedId ? requests.get(selectedId) : null;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 p-2 border-b">
        {hookEnabled ? (
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2.5 text-xs text-red-500 hover:text-red-600"
            onClick={() => handleToggleHook(false)}
            disabled={hookLoading || status !== Status.Ready}
          >
            {hookLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Square className="w-3.5 h-3.5" />
            )}
            Stop
          </Button>
        ) : (
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2.5 text-xs text-green-600 hover:text-green-700"
            onClick={() => handleToggleHook(true)}
            disabled={hookLoading || status !== Status.Ready}
          >
            {hookLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5" />
            )}
            Start
          </Button>
        )}
        <a
          href={`/api/history/http/${device}/${identifier}/har`}
          download={`${identifier}-http.har`}
          className={
            buttonVariants({ variant: "outline", size: "sm" }) +
            " h-8 px-2.5 text-xs no-underline"
          }
        >
          <Download className="w-3.5 h-3.5" />
          Export HAR
        </a>
        <span className="text-xs text-muted-foreground ml-auto">
          {requestList.length} request{requestList.length !== 1 ? "s" : ""}
        </span>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8"
          onClick={() =>
            tableEndRef.current?.scrollIntoView({ behavior: "smooth" })
          }
        >
          <ChevronsDown className="w-4 h-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-red-500 hover:text-red-600 hover:bg-red-100 dark:hover:bg-red-950/30"
          onClick={handleClear}
        >
          <Trash2 className="w-4 h-4" />
        </Button>
      </div>

      <ResizablePanelGroup orientation="vertical" className="flex-1">
        <ResizablePanel
          defaultSize={selectedRequest ? "50%" : "100%"}
          minSize="20%"
        >
          <ScrollArea className="h-full">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-16">Method</TableHead>
                  <TableHead>URL</TableHead>
                  <TableHead className="w-16">Status</TableHead>
                  <TableHead className="w-24">MIME</TableHead>
                  <TableHead className="w-16">Size</TableHead>
                  <TableHead className="w-16">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {requestList.map((req) => (
                  <TableRow
                    key={req.id}
                    className={`cursor-pointer ${selectedId === req.id ? "bg-accent" : ""} ${req.error ? "text-red-500" : ""}`}
                    onClick={() =>
                      setSelectedId(selectedId === req.id ? null : req.id)
                    }
                  >
                    <TableCell className="font-mono text-xs">
                      {req.method}
                    </TableCell>
                    <TableCell
                      className="font-mono text-xs max-w-md truncate"
                      title={req.url}
                    >
                      {req.url}
                    </TableCell>
                    <TableCell
                      className={`font-mono text-xs ${statusColor(req.statusCode)}`}
                    >
                      {req.statusCode ?? (req.error ? "ERR" : "-")}
                    </TableCell>
                    <TableCell className="text-xs truncate max-w-24">
                      {req.isWebSocket
                        ? `websocket (${req.wsMessages?.length ?? 0})`
                        : (req.mimeType ?? "-")}
                    </TableCell>
                    <TableCell className="text-xs">
                      {req.size > 0n ? formatSize(req.size) : "-"}
                    </TableCell>
                    <TableCell className="text-xs">
                      {formatDuration(req.duration)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div ref={tableEndRef} />
          </ScrollArea>
        </ResizablePanel>

        {selectedRequest && (
          <>
            <ResizableHandle />
            <ResizablePanel defaultSize="50%" minSize="20%">
              <Tabs defaultValue="request" className="h-full flex flex-col">
                <TabsList variant="line" className="mx-2 mt-2">
                  <TabsTrigger value="request">Request</TabsTrigger>
                  <TabsTrigger value="response">Response</TabsTrigger>
                  {selectedRequest.backtrace &&
                    selectedRequest.backtrace.length > 0 && (
                    <TabsTrigger value="backtrace">Backtrace</TabsTrigger>
                  )}
                  {selectedRequest.isWebSocket && (
                    <TabsTrigger value="messages">
                      Messages
                      {selectedRequest.wsMessages
                        ? ` (${selectedRequest.wsMessages.length})`
                        : ""}
                    </TabsTrigger>
                  )}
                </TabsList>

                <TabsContent value="request" className="overflow-auto">
                  <ScrollArea className="h-full">
                    {(() => {
                      const parsed = parseUrl(selectedRequest.url);
                      return (
                        <div className="p-3">
                          <div>
                            <div className="text-xs font-semibold text-muted-foreground mb-1">
                              General
                            </div>
                            <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                              {selectedRequest.method} {parsed.pathname}
                              {`\nHost: ${parsed.host}`}
                            </pre>
                            <CopyAsButtons
                              request={{
                                method: selectedRequest.method,
                                url: selectedRequest.url,
                                headers: selectedRequest.requestHeaders,
                                body: selectedRequest.requestBody,
                              }}
                            />
                          </div>
                          <div className="grid grid-cols-2 gap-3 mt-3">
                            <div className="space-y-3">
                              {parsed.params.length > 0 && (
                                <div>
                                  <div className="text-xs font-semibold text-muted-foreground mb-1">
                                    Query Parameters
                                  </div>
                                  <div className="space-y-0.5">
                                    {parsed.params.map(([k, v], i) => (
                                      <div
                                        key={i}
                                        className="text-xs font-mono break-all"
                                      >
                                        <span className="text-muted-foreground">
                                          {k}:
                                        </span>{" "}
                                        {v}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                              <div>
                                <div className="text-xs font-semibold text-muted-foreground mb-1">
                                  Headers
                                </div>
                                <HeadersView
                                  headers={selectedRequest.requestHeaders}
                                />
                              </div>
                            </div>
                            <div>
                              <div className="text-xs font-semibold text-muted-foreground mb-1">
                                Body
                              </div>
                              <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                                {selectedRequest.requestBody || "(none)"}
                              </pre>
                            </div>
                          </div>
                        </div>
                      );
                    })()}
                  </ScrollArea>
                </TabsContent>

                <TabsContent
                  value="response"
                  className="overflow-hidden h-full"
                >
                  <div className="grid grid-cols-2 h-full min-h-0">
                    <ScrollArea className="h-full border-r overflow-hidden">
                      <div className="p-3 space-y-3">
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-1">
                            Status
                          </div>
                          <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                            {selectedRequest.statusCode ?? "Pending"}
                            {selectedRequest.error &&
                              ` (Error: ${selectedRequest.error})`}
                          </pre>
                        </div>
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-1">
                            Headers
                          </div>
                          <HeadersView
                            headers={selectedRequest.responseHeaders}
                          />
                        </div>
                      </div>
                    </ScrollArea>
                    <div className="h-full flex flex-col overflow-hidden">
                      <div className="flex items-center gap-2 p-3 pb-0">
                        <div className="text-xs font-semibold text-muted-foreground">
                          Body
                        </div>
                        {selectedRequest.attachment && (
                          <a
                            href={`/api/history/http/${device}/${identifier}/attachment/${encodeURIComponent(selectedRequest.id)}`}
                            download={selectedRequest.id}
                            className="inline-flex items-center gap-1 h-5 px-1.5 text-[10px] border rounded border-input text-foreground hover:bg-accent transition"
                          >
                            <Download className="w-3 h-3" />
                            Download
                          </a>
                        )}
                      </div>
                      <div className="flex-1 min-h-0 p-3">
                        {selectedRequest.attachment ? (
                          <HttpResponseBodyView
                            url={`/api/history/http/${device}/${identifier}/attachment/${encodeURIComponent(selectedRequest.id)}`}
                            mime={selectedRequest.mimeType}
                          />
                        ) : (
                          <span className="text-xs text-muted-foreground">
                            (none)
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                {selectedRequest.backtrace &&
                  selectedRequest.backtrace.length > 0 && (
                  <TabsContent value="backtrace" className="overflow-auto">
                    <ScrollArea className="h-full">
                      <div className="p-3">
                        <div className="rounded border bg-muted/20 p-2 overflow-auto max-h-60 text-[10px] font-mono space-y-0.5">
                          {selectedRequest.backtrace.map((frame, i) => (
                            <div key={i} className="p-1 rounded hover:bg-muted/50 break-all">
                              <span className="text-muted-foreground mr-2">#{i}</span>
                              {frame}
                            </div>
                          ))}
                        </div>
                      </div>
                    </ScrollArea>
                  </TabsContent>
                )}

                {selectedRequest.isWebSocket && (
                  <TabsContent value="messages" className="overflow-auto">
                    <ScrollArea className="h-full">
                      <div className="p-3">
                        {!selectedRequest.wsMessages?.length ? (
                          <div className="text-xs text-muted-foreground text-center py-4">
                            No messages yet
                          </div>
                        ) : (
                          <div className="space-y-1">
                            {selectedRequest.wsMessages.map((msg, i) => (
                              <div
                                key={i}
                                className={`flex items-start gap-2 text-xs font-mono p-1.5 rounded ${
                                  msg.direction === "send"
                                    ? "bg-blue-50 dark:bg-blue-950/30"
                                    : "bg-green-50 dark:bg-green-950/30"
                                }`}
                              >
                                {msg.direction === "send" ? (
                                  <ArrowUp className="w-3 h-3 mt-0.5 text-blue-500 shrink-0" />
                                ) : (
                                  <ArrowDown className="w-3 h-3 mt-0.5 text-green-500 shrink-0" />
                                )}
                                <div className="min-w-0 flex-1">
                                  {msg.message ? (
                                    <pre className="whitespace-pre-wrap break-all">
                                      {msg.message}
                                    </pre>
                                  ) : (
                                    <span className="text-muted-foreground">
                                      [{msg.messageType}
                                      {msg.dataLength !== undefined &&
                                        ` ${formatSize(msg.dataLength)}`}
                                      ]
                                    </span>
                                  )}
                                  {msg.error && (
                                    <span className="text-red-500">
                                      {" "}
                                      Error: {msg.error}
                                    </span>
                                  )}
                                </div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </ScrollArea>
                  </TabsContent>
                )}
              </Tabs>
            </ResizablePanel>
          </>
        )}
      </ResizablePanelGroup>
    </div>
  );
}
