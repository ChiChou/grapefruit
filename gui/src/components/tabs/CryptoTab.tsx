import {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
} from "react";
import { useTranslation } from "react-i18next";
import { useVirtualizer } from "@tanstack/react-virtual";
import {
  ChevronRight,
  Trash2,
  ChevronsDown,
  Loader2,
  Play,
  Square,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { useSession, Status, Platform } from "@/context/SessionContext";
import { useFruityQuery, useDroidQuery } from "@/lib/queries";
import { useLogStream } from "@/hooks/useLogStream";
import { toTime } from "@/lib/format";

import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";

interface CryptoEntry {
  id: number;
  timestamp: Date;
  message: BaseHookMessage;
  data?: ArrayBuffer;
}

const ROW_HEIGHT = 32;

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

const CRYPTO_PIN_ID = "crypto";

function CryptoRow({
  entry,
  style,
  selectedId,
  onSelect,
}: {
  entry: CryptoEntry;
  style: React.CSSProperties;
  selectedId: number | null;
  onSelect: (id: number) => void;
}) {

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
      <span className="text-muted-foreground font-mono w-24 shrink-0">
        {toTime(timestamp)}
      </span>
      <Badge
        variant={message.dir === "enter" ? "default" : "secondary"}
        className="h-5 px-1.5 text-[10px] shrink-0"
      >
        <ChevronRight
          className={`h-3 w-3 ${message.dir === "leave" ? "rotate-180" : ""}`}
        />
      </Badge>
      <span
        className="font-mono text-primary truncate w-40 shrink-0"
        title={message.symbol}
      >
        {message.symbol}
      </span>
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
      {extra?.detailType && (
        <Badge variant="secondary" className="h-5 px-1.5 text-[10px] shrink-0">
          {extra.detailType}
          {extra.len !== undefined && ` ${extra.len}B`}
        </Badge>
      )}
      <span
        className="font-mono text-muted-foreground truncate flex-1 min-w-0"
        title={message.line || ""}
      >
        {message.line || ""}
      </span>
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

const mapHistory = (record: Record<string, unknown>, id: number): CryptoEntry => ({
  id,
  timestamp: new Date(record.timestamp as string),
  message: {
    subject: "crypto",
    category: (record.category as string) || "unknown",
    symbol: record.symbol as string,
    dir: record.direction as "enter" | "leave",
    line: (record.line as string) ?? undefined,
    extra: record.extra as Record<string, unknown> | undefined,
    backtrace: record.backtrace as string[] | undefined,
  },
  data: record.data ? base64ToArrayBuffer(record.data as string) : undefined,
});

const mapSocket = (id: number, ...args: unknown[]): CryptoEntry => ({
  id,
  timestamp: new Date(),
  message: args[0] as BaseHookMessage,
  data: args[1] as ArrayBuffer | undefined,
});

export function CryptoTab() {
  const { t } = useTranslation();
  const { fruity, droid, status, device, identifier, platform } = useSession();
  const isDroid = platform === Platform.Droid;

  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  const {
    entries,
    selectedId,
    setSelectedId,
    selectedEntry,
    clear,
  } = useLogStream<CryptoEntry>({
    event: "crypto",
    path: "history/crypto",
    key: "logs",
    fromRecord: mapHistory,
    fromEvent: mapSocket,
    max: 10000,
  });

  const handleSelect = useCallback((id: number) => {
    setSelectedId(selectedId === id ? null : id);
  }, [selectedId, setSelectedId]);

  // Single toggle state for all crypto hooks
  const [hookEnabled, setHookEnabled] = useState<boolean | null>(null);
  const [hookLoading, setHookLoading] = useState(false);
  const [filter, setFilter] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<Set<string>>(new Set());

  // Fetch crypto pin status (platform-aware)
  const { data: fruityInitActive } = useFruityQuery<boolean>(
    ["cryptoActive", device ?? "", identifier ?? ""],
    (api) => api.pins.active(CRYPTO_PIN_ID),
    { enabled: !isDroid },
  );
  const { data: droidInitActive } = useDroidQuery<boolean>(
    ["cryptoActive", device ?? "", identifier ?? ""],
    (api) => api.pins.active(CRYPTO_PIN_ID),
    { enabled: isDroid },
  );

  const initialActive = isDroid ? droidInitActive : fruityInitActive;

  useEffect(() => {
    if (initialActive !== undefined && hookEnabled === null) {
      setHookEnabled(initialActive);
    }
  }, [initialActive, hookEnabled]);

  const handleToggleHook = async (enabled: boolean) => {
    const api = isDroid ? droid : fruity;
    if (!api) return;

    setHookLoading(true);
    try {
      if (enabled) {
        await api.pins.start(CRYPTO_PIN_ID);
      } else {
        await api.pins.stop(CRYPTO_PIN_ID);
      }
      setHookEnabled(enabled);
    } catch (error) {
      console.error(
        `Failed to ${enabled ? "start" : "stop"} crypto hooks:`,
        error,
      );
    } finally {
      setHookLoading(false);
    }
  };

  // Collect unique categories from all entries
  const categories = useMemo(() => {
    const cats = new Set<string>();
    for (const e of entries) {
      if (e.message.category) cats.add(e.message.category);
    }
    return Array.from(cats).sort();
  }, [entries]);

  const toggleCategory = useCallback((cat: string) => {
    setCategoryFilter((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }, []);

  const filteredEntries = useMemo(() => {
    let result = entries;
    if (categoryFilter.size > 0) {
      result = result.filter((e) => categoryFilter.has(e.message.category));
    }
    if (filter) {
      const lower = filter.toLowerCase();
      result = result.filter((e) => {
        const extra = e.message.extra as Record<string, unknown> | undefined;
        return (
          e.message.symbol?.toLowerCase().includes(lower) ||
          e.message.line?.toLowerCase().includes(lower) ||
          (extra?.op as string)?.toLowerCase().includes(lower) ||
          (extra?.algo as string)?.toLowerCase().includes(lower) ||
          (extra?.detailType as string)?.toLowerCase().includes(lower)
        );
      });
    }
    return result;
  }, [entries, filter, categoryFilter]);

  const virtualizer = useVirtualizer({
    count: filteredEntries.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  // Auto-scroll when new entries arrive
  useEffect(() => {
    if (autoScroll && filteredEntries.length > 0) {
      requestAnimationFrame(() => {
        virtualizer.scrollToIndex(filteredEntries.length - 1, { align: "end" });
      });
    }
  }, [filteredEntries.length, autoScroll, virtualizer]);

  // Track scroll position to detect near-bottom for auto-scroll
  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onScroll = () => {
      const isNearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - ROW_HEIGHT * 3;
      setAutoScroll((prev) => (prev === isNearBottom ? prev : isNearBottom));
    };
    el.addEventListener("scroll", onScroll, { passive: true });
    return () => el.removeEventListener("scroll", onScroll);
  }, []);

  const scrollToLatest = useCallback(() => {
    if (filteredEntries.length > 0) {
      virtualizer.scrollToIndex(filteredEntries.length - 1, { align: "end" });
      setAutoScroll(true);
    }
  }, [filteredEntries.length, virtualizer]);

  const isDisabled = status !== Status.Ready;

  return (
    <div className="h-full flex flex-col">
      {/* Header with single toggle + filter */}
      <div className="flex items-center gap-2 px-3 py-2 border-b bg-muted/30">
        {hookEnabled ? (
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2.5 text-xs text-red-500 hover:text-red-600"
            onClick={() => handleToggleHook(false)}
            disabled={hookLoading || isDisabled}
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
            disabled={hookLoading || isDisabled}
          >
            {hookLoading ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5" />
            )}
            Start
          </Button>
        )}
        <Input
          placeholder={t("filter")}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="h-8 text-xs max-w-xs"
        />
        {categories.length > 0 &&
          categories.map((cat) => (
            <Button
              key={cat}
              variant={categoryFilter.has(cat) ? "default" : "outline"}
              size="sm"
              className="h-6 px-2 text-[11px]"
              onClick={() => toggleCategory(cat)}
            >
              {cat}
            </Button>
          ))}
        <div className="flex items-center gap-2 ml-auto">
          <span className="text-xs text-muted-foreground">
            {filter || categoryFilter.size > 0
              ? `${filteredEntries.length.toLocaleString()} / ${entries.length.toLocaleString()}`
              : entries.length.toLocaleString()}
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
            onClick={clear}
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
          <div ref={scrollRef} className="h-full overflow-auto">
            {filteredEntries.length === 0 ? (
              <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
                <span>{entries.length === 0 ? t("crypto_no_results") : t("no_matching_entries")}</span>
              </div>
            ) : (
              <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                {virtualizer.getVirtualItems().map((vItem) => {
                  const entry = filteredEntries[vItem.index];
                  return (
                    <CryptoRow
                      key={vItem.key}
                      entry={entry}
                      style={{ height: vItem.size, transform: `translateY(${vItem.start}px)`, position: "absolute", left: 0, right: 0 }}
                      selectedId={selectedId}
                      onSelect={handleSelect}
                    />
                  );
                })}
              </div>
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
