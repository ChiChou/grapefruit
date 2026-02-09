import { useCallback, useEffect, useRef, useState } from "react";
import {
  Play,
  Square,
  Trash2,
  Copy,
  Check,
  ArrowUp,
  ArrowDown,
} from "lucide-react";

import { Button } from "@/components/ui/button";
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

import { useSession, Status } from "@/context/SessionContext";
import { useRpcMutation } from "@/lib/queries";

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
  responseBody?: string;
  error?: string;
  mechanism?: string;
  isWebSocket?: boolean;
  wsMessages?: WebSocketMessage[];
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

function generateCurl(req: CapturedRequest): string {
  let cmd = `curl '${req.url}'`;
  if (req.method !== "GET") cmd += ` -X ${req.method}`;
  for (const [k, v] of Object.entries(req.requestHeaders)) {
    cmd += ` \\\n  -H '${k}: ${v}'`;
  }
  if (req.requestBody) cmd += ` \\\n  --data-raw '${req.requestBody}'`;
  return cmd;
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

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button variant="outline" size="sm" onClick={handleCopy}>
      {copied ? (
        <Check className="w-4 h-4 mr-1" />
      ) : (
        <Copy className="w-4 h-4 mr-1" />
      )}
      {copied ? "Copied" : "Copy"}
    </Button>
  );
}

export function HttpLogTab() {
  const { socket, status } = useSession();
  const [requests, setRequests] = useState<Map<string, CapturedRequest>>(
    () => new Map(),
  );
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [capturing, setCapturing] = useState(false);
  const tableEndRef = useRef<HTMLDivElement>(null);

  const startMutation = useRpcMutation<void, void>(
    (api) => api.httplog.start(),
    { onSuccess: () => setCapturing(true) },
  );

  const stopMutation = useRpcMutation<void, void>((api) => api.httplog.stop(), {
    onSuccess: () => setCapturing(false),
  });

  const startedRef = useRef(false);

  const handleEvent = useCallback((event: any) => {
    setRequests((prev) => {
      const next = new Map(prev);
      const { type, requestId } = event;

      function getOrCreate(id: string): CapturedRequest {
        let entry = next.get(id);
        if (!entry) {
          entry = {
            id,
            method: "",
            url: "",
            requestHeaders: {},
            size: 0n,
            startTime: event.timestamp,
          };
          next.set(id, entry);
        }
        return entry;
      }

      switch (type) {
        case "requestWillBeSent": {
          const req = event.request;
          const entry = getOrCreate(requestId);
          entry.method = req.method;
          entry.url = req.url;
          entry.requestHeaders = req.headers || {};
          entry.requestBody = req.body;
          break;
        }
        case "responseReceived": {
          const entry = getOrCreate(requestId);
          const resp = event.response;
          entry.statusCode = resp.statusCode;
          entry.mimeType = resp.mimeType;
          entry.responseHeaders = resp.headers;
          if (resp.url && !entry.url) entry.url = resp.url;
          break;
        }
        case "dataReceived": {
          const entry = getOrCreate(requestId);
          try {
            entry.size += BigInt(event.dataLength);
          } catch {
            /* ignore invalid */
          }
          break;
        }
        case "loadingFinished": {
          const entry = getOrCreate(requestId);
          entry.responseBody = event.responseBody;
          entry.endTime = event.timestamp;
          entry.duration = event.timestamp - entry.startTime;
          break;
        }
        case "loadingFailed": {
          const entry = getOrCreate(requestId);
          entry.error = event.error;
          entry.endTime = event.timestamp;
          entry.duration = event.timestamp - entry.startTime;
          break;
        }
        case "mechanism": {
          const entry = getOrCreate(requestId);
          entry.mechanism = event.mechanism;
          break;
        }
        case "webSocketSend":
        case "webSocketReceive": {
          const entry = getOrCreate(requestId);
          entry.isWebSocket = true;
          if (!entry.method) entry.method = "WS";
          if (!entry.wsMessages) entry.wsMessages = [];
          entry.wsMessages.push({
            direction: type === "webSocketSend" ? "send" : "receive",
            messageType: event.messageType,
            message: event.message,
            dataLength: event.dataLength,
            error: event.error,
            timestamp: event.timestamp,
          });
          break;
        }
      }

      return next;
    });
  }, []);

  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    socket.on("httplog", handleEvent);

    // Auto-start capture on tab load
    if (!startedRef.current) {
      startedRef.current = true;
      startMutation.mutate();
    }

    return () => {
      socket.off("httplog", handleEvent);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [socket, status, handleEvent]);

  const handleClear = () => {
    setRequests(new Map());
    setSelectedId(null);
  };

  const requestList = Array.from(requests.values());
  const selectedRequest = selectedId ? requests.get(selectedId) : null;

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 p-2 border-b">
        {capturing ? (
          <Button
            variant="outline"
            size="sm"
            onClick={() => stopMutation.mutate()}
            disabled={stopMutation.isPending}
          >
            <Square className="w-4 h-4 mr-1" />
            Stop
          </Button>
        ) : (
          <Button
            variant="outline"
            size="sm"
            onClick={() => startMutation.mutate()}
            disabled={startMutation.isPending}
          >
            <Play className="w-4 h-4 mr-1" />
            Start
          </Button>
        )}
        <Button variant="outline" size="sm" onClick={handleClear}>
          <Trash2 className="w-4 h-4 mr-1" />
          Clear
        </Button>
        <span className="text-xs text-muted-foreground ml-auto">
          {requestList.length} request{requestList.length !== 1 ? "s" : ""}
        </span>
      </div>

      <ResizablePanelGroup direction="vertical" className="flex-1">
        {/* Request List */}
        <ResizablePanel defaultSize={selectedRequest ? 50 : 100} minSize={20}>
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
            <ResizablePanel defaultSize={50} minSize={20}>
              <Tabs defaultValue="request" className="h-full flex flex-col">
                <TabsList className="mx-2 mt-2">
                  <TabsTrigger value="request">Request</TabsTrigger>
                  <TabsTrigger value="response">Response</TabsTrigger>
                  <TabsTrigger value="curl">cURL</TabsTrigger>
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
                        <div className="p-3 space-y-3">
                          <div>
                            <div className="text-xs font-semibold text-muted-foreground mb-1">
                              General
                            </div>
                            <pre className="text-xs font-mono whitespace-pre-wrap break-all">
                              {selectedRequest.method} {parsed.pathname}
                              {`\nHost: ${parsed.host}`}
                              {selectedRequest.mechanism &&
                                `\nMechanism: ${selectedRequest.mechanism}`}
                            </pre>
                          </div>
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
                          <div className="grid grid-cols-2 gap-3">
                            <div>
                              <div className="text-xs font-semibold text-muted-foreground mb-1">
                                Headers
                              </div>
                              <HeadersView
                                headers={selectedRequest.requestHeaders}
                              />
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

                <TabsContent value="response" className="overflow-auto">
                  <ScrollArea className="h-full">
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
                      <div className="grid grid-cols-2 gap-3">
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-1">
                            Headers
                          </div>
                          <HeadersView
                            headers={selectedRequest.responseHeaders}
                          />
                        </div>
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-1">
                            Body
                          </div>
                          <pre className="text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-auto">
                            {selectedRequest.responseBody || "(none)"}
                          </pre>
                        </div>
                      </div>
                    </div>
                  </ScrollArea>
                </TabsContent>

                <TabsContent value="curl" className="overflow-auto">
                  <ScrollArea className="h-full">
                    <div className="p-3 space-y-2">
                      <div className="flex justify-end">
                        <CopyButton text={generateCurl(selectedRequest)} />
                      </div>
                      <pre className="text-xs font-mono bg-muted p-2 rounded whitespace-pre-wrap break-all">
                        {generateCurl(selectedRequest)}
                      </pre>
                    </div>
                  </ScrollArea>
                </TabsContent>

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
