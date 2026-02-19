import {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
  type CSSProperties,
} from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { List, type ListImperativeAPI } from "react-window";
import { ChevronRight, Trash2, ChevronsDown } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { useSession, Status, Platform } from "@/context/SessionContext";
import { useRpcQuery, useDroidRpcQuery } from "@/lib/queries";

import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";

interface CryptoEntry {
  id: number;
  timestamp: Date;
  message: BaseHookMessage;
  data?: ArrayBuffer;
}

const ROW_HEIGHT = 32;
const MAX_ENTRIES = 10000;
const THROTTLE_MS = 100;

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const bin = atob(base64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return buf.buffer;
}

function formatHexDump(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  const lines: string[] = [];
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16);
    const addr = offset.toString(16).padStart(8, "0");
    const hexParts: string[] = [];
    for (let i = 0; i < 16; i += 2) {
      if (i < chunk.length) {
        const h = chunk[i].toString(16).padStart(2, "0");
        const h2 =
          i + 1 < chunk.length
            ? chunk[i + 1].toString(16).padStart(2, "0")
            : "  ";
        hexParts.push(h + h2);
      } else {
        hexParts.push("    ");
      }
    }
    const ascii = Array.from(chunk)
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
      .join("")
      .padEnd(16);
    lines.push(`${addr}: ${hexParts.join(" ")}  ${ascii}`);
  }
  return lines.join("\n");
}

const FRUITY_CRYPTO_GROUPS = ["cccrypt", "x509", "hash", "hmac"] as const;
const DROID_CRYPTO_GROUPS = ["cipher", "pbkdf", "keygen"] as const;

function formatTime(date: Date): string {
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}

interface CryptoRowProps {
  entries: CryptoEntry[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

function CryptoRow(
  props: {
    ariaAttributes: {
      "aria-posinset": number;
      "aria-setsize": number;
      role: "listitem";
    };
    index: number;
    style: CSSProperties;
  } & CryptoRowProps,
) {
  const { index, style, entries, selectedId, onSelect } = props;
  const entry = entries[index];

  if (!entry) return null;

  const { message, timestamp, data } = entry;
  const isSelected = selectedId === entry.id;
  const extra = message.extra as
    | { op?: string; algo?: string; detailType?: string; len?: number }
    | undefined;

  return (
    <div
      style={style}
      className={`flex items-center px-3 py-1 border-b border-border/50 hover:bg-muted/30 text-xs gap-2 cursor-pointer ${isSelected ? "bg-accent" : ""}`}
      onClick={() => onSelect(entry.id)}
    >
      {/* Timestamp */}
      <span className="text-muted-foreground font-mono w-24 shrink-0">
        {formatTime(timestamp)}
      </span>

      {/* Direction */}
      <Badge
        variant={message.dir === "enter" ? "default" : "secondary"}
        className="h-5 px-1.5 text-[10px] shrink-0"
      >
        <ChevronRight
          className={`h-3 w-3 ${message.dir === "leave" ? "rotate-180" : ""}`}
        />
      </Badge>

      {/* Symbol */}
      <span
        className="font-mono text-primary truncate w-40 shrink-0"
        title={message.symbol}
      >
        {message.symbol}
      </span>

      {/* Op + Algo badges */}
      {extra?.op && (
        <Badge variant="outline" className="h-5 px-1.5 text-[10px] shrink-0">
          {extra.op}
        </Badge>
      )}
      {extra?.algo && (
        <Badge variant="outline" className="h-5 px-1.5 text-[10px] shrink-0">
          {extra.algo}
        </Badge>
      )}

      {/* Detail type + size */}
      {extra?.detailType && (
        <Badge variant="secondary" className="h-5 px-1.5 text-[10px] shrink-0">
          {extra.detailType}
          {extra.len !== undefined && ` ${extra.len}B`}
        </Badge>
      )}

      {/* Line summary */}
      <span
        className="font-mono text-muted-foreground truncate flex-1 min-w-0"
        title={message.line || ""}
      >
        {message.line || ""}
      </span>

      {/* Data indicator */}
      {data && (
        <Badge variant="secondary" className="h-5 px-1.5 text-[10px] shrink-0">
          {data.byteLength}B
        </Badge>
      )}
    </div>
  );
}

const CRYPTO_DETAIL_TAB_STATE = "CRYPTO_DETAIL_TAB_STATE";

function DetailPanel({ entry }: { entry: CryptoEntry }) {
  const { t } = useTranslation();
  const { message, data } = entry;
  const extra = message.extra as Record<string, unknown> | undefined;

  const hasData = !!data;
  const hasBt = !!message.backtrace?.length;

  const savedTab = localStorage.getItem(CRYPTO_DETAIL_TAB_STATE);
  const availableTabs = [
    "detail",
    ...(hasData ? ["hexdump"] : []),
    ...(hasBt ? ["backtrace"] : []),
  ];
  const defaultTab =
    savedTab && availableTabs.includes(savedTab)
      ? savedTab
      : hasData
        ? "hexdump"
        : hasBt
          ? "backtrace"
          : "detail";

  return (
    <Tabs
      defaultValue={defaultTab}
      onValueChange={(v) => localStorage.setItem(CRYPTO_DETAIL_TAB_STATE, v)}
      className="h-full flex flex-col"
    >
      <TabsList variant="line" className="mx-2 mt-2 shrink-0">
        <TabsTrigger value="detail">{t("crypto_detail_tab")}</TabsTrigger>
        {hasData && (
          <TabsTrigger value="hexdump">{t("crypto_hexdump_tab")}</TabsTrigger>
        )}
        {hasBt && (
          <TabsTrigger value="backtrace">
            {t("crypto_backtrace_tab")}
          </TabsTrigger>
        )}
      </TabsList>

      <TabsContent value="detail" className="flex-1 min-h-0">
        <ScrollArea className="h-full">
          <div className="p-3 space-y-3">
            <div>
              <div className="text-xs font-semibold text-muted-foreground mb-1">
                Symbol
              </div>
              <pre className="text-xs font-mono break-all">
                {message.symbol}
              </pre>
            </div>
            <div>
              <div className="text-xs font-semibold text-muted-foreground mb-1">
                Direction
              </div>
              <Badge
                variant={message.dir === "enter" ? "default" : "secondary"}
                className="text-xs"
              >
                {message.dir}
              </Badge>
            </div>
            {message.line && (
              <div>
                <div className="text-xs font-semibold text-muted-foreground mb-1">
                  Detail
                </div>
                <pre className="text-xs font-mono whitespace-pre-wrap break-all bg-muted p-2 rounded select-all">
                  {message.line}
                </pre>
              </div>
            )}
            {extra && Object.keys(extra).length > 0 && (
              <div>
                <div className="text-xs font-semibold text-muted-foreground mb-1">
                  Extra
                </div>
                <div className="space-y-0.5">
                  {Object.entries(extra).map(([k, v]) => (
                    <div key={k} className="text-xs font-mono break-all">
                      <span className="text-blue-500 dark:text-blue-400">
                        {k}
                      </span>
                      <span className="text-muted-foreground">: </span>
                      <span>{String(v)}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </ScrollArea>
      </TabsContent>

      {hasData && (
        <TabsContent value="hexdump" className="flex-1 min-h-0">
          <ScrollArea className="h-full">
            <div className="p-3">
              <div className="text-xs text-muted-foreground mb-2">
                {data.byteLength} bytes
              </div>
              <pre className="font-mono text-[11px] leading-5 select-all">
                {formatHexDump(data)}
              </pre>
            </div>
          </ScrollArea>
        </TabsContent>
      )}

      {hasBt && (
        <TabsContent value="backtrace" className="flex-1 min-h-0">
          <ScrollArea className="h-full">
            <div className="p-2 font-mono text-xs space-y-1">
              {message.backtrace!.map((frame, index) => (
                <div
                  key={index}
                  className="p-1.5 rounded hover:bg-muted/50 break-all"
                >
                  <span className="text-muted-foreground mr-2">#{index}</span>
                  {frame}
                </div>
              ))}
            </div>
          </ScrollArea>
        </TabsContent>
      )}
    </Tabs>
  );
}

export function CryptoResultsView() {
  const { t } = useTranslation();
  const { fruity, droid, socket, status, device, identifier, platform } =
    useSession();
  const isDroid = platform === Platform.Droid;
  const cryptoGroups = isDroid ? DROID_CRYPTO_GROUPS : FRUITY_CRYPTO_GROUPS;
  const [entries, setEntries] = useState<CryptoEntry[]>([]);
  const listRef = useRef<ListImperativeAPI>(null);
  const idCounterRef = useRef(0);
  const pendingEntriesRef = useRef<CryptoEntry[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastUpdateRef = useRef<number>(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [listHeight, setListHeight] = useState(300);
  const [autoScroll, setAutoScroll] = useState(true);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const handleSelect = useCallback((id: number) => {
    setSelectedId((prev) => (prev === id ? null : id));
  }, []);

  // Crypto sub-group toggle state
  const [cryptoStatus, setCryptoStatus] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  // Fetch crypto sub-group status (platform-aware)
  const { data: fruityInitStatus } = useRpcQuery<Record<string, boolean>>(
    ["cryptoStatus", device ?? "", identifier ?? ""],
    (api) => api.crypto.status(),
    { enabled: !isDroid },
  );
  const { data: droidInitStatus } = useDroidRpcQuery<Record<string, boolean>>(
    ["cryptoStatus", device ?? "", identifier ?? ""],
    (api) => api.crypto.status(),
    { enabled: isDroid },
  );

  const initialStatus = isDroid ? droidInitStatus : fruityInitStatus;

  useEffect(() => {
    if (initialStatus) {
      setCryptoStatus(initialStatus);
    }
  }, [initialStatus]);

  const handleToggle = async (groupId: string, enabled: boolean) => {
    const api = isDroid ? droid : fruity;
    if (!api) return;

    setLoading((prev) => ({ ...prev, [groupId]: true }));

    try {
      if (enabled) {
        await api.crypto.start(groupId);
      } else {
        await api.crypto.stop(groupId);
      }
      setCryptoStatus((prev) => ({ ...prev, [groupId]: enabled }));
    } catch (error) {
      console.error(
        `Failed to ${enabled ? "start" : "stop"} crypto group ${groupId}:`,
        error,
      );
    } finally {
      setLoading((prev) => ({ ...prev, [groupId]: false }));
    }
  };

  // Load historical crypto logs
  const { data: cryptoHistory } = useQuery<{
    logs: {
      id: number;
      timestamp: string;
      symbol: string;
      direction: string;
      line: string | null;
      extra: Record<string, unknown> | undefined;
      backtrace?: string[];
      data?: string;
      createdAt: string;
    }[];
  }>({
    queryKey: ["cryptoHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(
        `/api/history/crypto/${device}/${identifier}?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load crypto history");
      return res.json();
    },
    enabled: !!device && !!identifier,
    staleTime: Infinity,
    gcTime: 0,
  });

  useEffect(() => {
    if (!cryptoHistory?.logs?.length) return;
    const historicalEntries: CryptoEntry[] = cryptoHistory.logs
      .slice()
      .reverse()
      .map((record) => ({
        id: idCounterRef.current++,
        timestamp: new Date(record.timestamp),
        message: {
          subject: "crypto",
          category: "crypto",
          symbol: record.symbol,
          dir: record.direction as "enter" | "leave",
          line: record.line ?? undefined,
          extra: record.extra,
          backtrace: record.backtrace,
        },
        data: record.data ? base64ToArrayBuffer(record.data) : undefined,
      }));
    setEntries(historicalEntries);
  }, [cryptoHistory]);

  // Resize observer
  useEffect(() => {
    if (!containerRef.current) return;

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setListHeight(entry.contentRect.height);
      }
    });

    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Throttled flush
  const flushPendingEntries = useCallback(() => {
    if (pendingEntriesRef.current.length === 0) return;

    const now = performance.now();
    if (now - lastUpdateRef.current < THROTTLE_MS) {
      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPendingEntries();
        });
      }
      return;
    }

    lastUpdateRef.current = now;
    const newEntries = pendingEntriesRef.current;
    pendingEntriesRef.current = [];

    setEntries((prev) => {
      const combined = [...prev, ...newEntries];
      if (combined.length > MAX_ENTRIES) {
        return combined.slice(-MAX_ENTRIES);
      }
      return combined;
    });

    if (autoScroll && listRef.current) {
      requestAnimationFrame(() => {
        listRef.current?.scrollToRow({
          index: entries.length + newEntries.length - 1,
          align: "end",
        });
      });
    }
  }, [autoScroll, entries.length, listRef]);

  // Handle incoming crypto messages
  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const handleCrypto = (message: BaseHookMessage, data?: ArrayBuffer) => {
      const entry: CryptoEntry = {
        id: idCounterRef.current++,
        timestamp: new Date(),
        message,
        data,
      };

      pendingEntriesRef.current.push(entry);

      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPendingEntries();
        });
      }
    };

    socket.on("crypto", handleCrypto);

    return () => {
      socket.off("crypto", handleCrypto);
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [socket, status, flushPendingEntries]);

  const handleRowsRendered = useCallback(
    (visibleRows: { startIndex: number; stopIndex: number }) => {
      const isNearBottom = visibleRows.stopIndex >= entries.length - 3;
      setAutoScroll(isNearBottom);
    },
    [entries.length],
  );

  const clearCryptoMutation = useMutation({
    mutationFn: async () => {
      if (!device || !identifier) return;
      const res = await fetch(`/api/history/crypto/${device}/${identifier}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to clear crypto logs");
    },
  });

  const handleClear = useCallback(() => {
    setEntries([]);
    setSelectedId(null);
    pendingEntriesRef.current = [];
    idCounterRef.current = 0;
    clearCryptoMutation.mutate();
  }, [clearCryptoMutation]);

  const scrollToLatest = useCallback(() => {
    if (listRef.current && entries.length > 0) {
      listRef.current.scrollToRow({ index: entries.length - 1, align: "end" });
      setAutoScroll(true);
    }
  }, [entries.length]);

  const selectedEntry = useMemo(
    () =>
      selectedId !== null ? entries.find((e) => e.id === selectedId) : null,
    [selectedId, entries],
  );

  const rowProps: CryptoRowProps = useMemo(
    () => ({ entries, selectedId, onSelect: handleSelect }),
    [entries, selectedId, handleSelect],
  );

  const isDisabled = status !== Status.Ready;

  return (
    <div className="h-full flex flex-col">
      {/* Header with toggles */}
      <div className="flex items-center justify-between px-3 py-2 border-b bg-muted/30">
        <div className="flex items-center gap-4">
          {cryptoGroups.map((group) => (
            <div key={group} className="flex items-center gap-1.5">
              <Switch
                id={`crypto-${group}`}
                checked={cryptoStatus[group] || false}
                onCheckedChange={(checked) => handleToggle(group, checked)}
                disabled={isDisabled || loading[group]}
                className="scale-75"
              />
              <Label
                htmlFor={`crypto-${group}`}
                className={`text-xs cursor-pointer ${loading[group] ? "animate-pulse" : ""}`}
              >
                {group}
              </Label>
            </div>
          ))}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">
            {entries.length.toLocaleString()}
          </span>
          {!autoScroll && (
            <Button
              variant="secondary"
              size="sm"
              onClick={scrollToLatest}
              className="h-6 px-2 text-[10px] gap-1"
            >
              <ChevronsDown className="h-3 w-3" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="sm"
            onClick={handleClear}
            className="h-7 px-2"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Two-column content */}
      <ResizablePanelGroup
        orientation="horizontal"
        className="flex-1 min-h-0"
        autoSaveId="crypto-results-split"
      >
        {/* Left: entry list */}
        <ResizablePanel
          defaultSize={selectedEntry ? "60%" : "100%"}
          minSize="30%"
        >
          <div ref={containerRef} className="h-full">
            {entries.length === 0 ? (
              <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                {t("crypto_no_results")}
              </div>
            ) : (
              <List
                listRef={listRef}
                style={{ height: listHeight, width: "100%" }}
                rowCount={entries.length}
                rowHeight={ROW_HEIGHT}
                rowProps={rowProps}
                rowComponent={CryptoRow}
                onRowsRendered={handleRowsRendered}
                overscanCount={20}
              />
            )}
          </div>
        </ResizablePanel>

        {/* Right: detail panel (only when selected) */}
        {selectedEntry && (
          <>
            <ResizableHandle />
            <ResizablePanel defaultSize="40%" minSize="20%">
              <DetailPanel key={selectedEntry.id} entry={selectedEntry} />
            </ResizablePanel>
          </>
        )}
      </ResizablePanelGroup>
    </div>
  );
}
