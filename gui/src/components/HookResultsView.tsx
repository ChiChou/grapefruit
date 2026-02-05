import {
  useEffect,
  useRef,
  useState,
  useCallback,
  useMemo,
  type CSSProperties,
} from "react";
import { useTranslation } from "react-i18next";
import { List, type ListImperativeAPI } from "react-window";
import {
  ChevronRight,
  Layers,
  Lock,
  Database,
  Trash2,
  ChevronsDown,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useSession, Status, Mode } from "@/context/SessionContext";
import {
  type HookMessage,
  type CryptoHookMessage,
  type SQLiteHookMessage,
} from "@/lib/rpc";

// Internal representation with timestamp
interface HookEntry {
  id: number;
  timestamp: Date;
  message: HookMessage;
}

const ROW_HEIGHT = 32;
const MAX_ENTRIES = 10000;
const THROTTLE_MS = 100;

// Category icon component
function CategoryIcon({ category }: { category: string }) {
  switch (category) {
    case "crypto":
      return <Lock className="h-3.5 w-3.5" />;
    case "sql":
      return <Database className="h-3.5 w-3.5" />;
    default:
      return <Layers className="h-3.5 w-3.5" />;
  }
}

// Format timestamp for display
function formatTime(date: Date): string {
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}

// Format message summary - no truncation, let CSS handle overflow
function formatSummary(message: HookMessage): string {
  if (message.category === "crypto") {
    const crypto = message as CryptoHookMessage;
    const parts: string[] = [];
    if (crypto.op) parts.push(crypto.op);
    if (crypto.algo) parts.push(crypto.algo);
    if (crypto.details?.type) parts.push(crypto.details.type);
    if (crypto.details?.len !== undefined) parts.push(`${crypto.details.len}B`);
    return parts.join(" | ");
  } else if (message.category === "sql") {
    const sql = message as SQLiteHookMessage;
    if (sql.sql) {
      return sql.sql;
    }
    if (sql.filename) {
      return sql.filename;
    }
    if (sql.bindValue !== undefined) {
      return `bind[${sql.bindIndex}] = ${sql.bindValue}`;
    }
  }
  return "";
}

// Stack trace popover component
function StackTracePopover({
  bt,
  t,
}: {
  bt?: string[];
  t: (key: string) => string;
}) {
  if (!bt || bt.length === 0) {
    return <span className="text-muted-foreground/30 text-xs px-2">--</span>;
  }

  return (
    <Popover>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-6 px-1.5">
          <Layers className="h-3 w-3" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[600px] p-0" align="end">
        <div className="p-3 border-b">
          <h4 className="font-medium text-sm">{t("hook_stack_trace")}</h4>
        </div>
        <ScrollArea className="h-[400px]">
          <div className="p-2 font-mono text-xs space-y-1">
            {bt.map((frame, index) => (
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
      </PopoverContent>
    </Popover>
  );
}

// Row props type for react-window v2 (custom props only - ariaAttributes, index, style are added by List)
interface HookRowProps {
  entries: HookEntry[];
  t: (key: string) => string;
}

// Row component for virtual list (react-window v2 API)
function HookRow(
  props: {
    ariaAttributes: {
      "aria-posinset": number;
      "aria-setsize": number;
      role: "listitem";
    };
    index: number;
    style: CSSProperties;
  } & HookRowProps,
) {
  const { index, style, entries, t } = props;
  const entry = entries[index];

  if (!entry) return null;

  const { message, timestamp } = entry;

  return (
    <div
      style={style}
      className="flex items-center px-3 py-1 border-b border-border/50 hover:bg-muted/30 text-xs gap-2"
    >
      {/* Timestamp */}
      <span className="text-muted-foreground font-mono w-24 shrink-0">
        {formatTime(timestamp)}
      </span>

      {/* Category */}
      <Badge
        variant="outline"
        className="flex items-center gap-1 h-5 px-1.5 shrink-0"
      >
        <CategoryIcon category={message.category} />
        <span className="text-[10px]">{message.category}</span>
      </Badge>

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
        className="font-mono text-primary truncate w-48 shrink-0"
        title={message.symbol}
      >
        {message.symbol}
      </span>

      {/* Summary */}
      <span
        className="font-mono text-muted-foreground truncate flex-1 min-w-0"
        title={formatSummary(message)}
      >
        {formatSummary(message)}
      </span>

      {/* Stack trace button */}
      <div className="shrink-0">
        <StackTracePopover bt={message.backtrace} t={t} />
      </div>
    </div>
  );
}

export function HookResultsView() {
  const { t } = useTranslation();
  const { socket, status, device, bundle, pid, mode } = useSession();
  const [entries, setEntries] = useState<HookEntry[]>([]);
  const listRef = useRef<ListImperativeAPI>(null);
  const idCounterRef = useRef(0);
  const pendingEntriesRef = useRef<HookEntry[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastUpdateRef = useRef<number>(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [listHeight, setListHeight] = useState(300);
  const historyLoadedRef = useRef(false);

  // Auto-scroll state
  const [autoScroll, setAutoScroll] = useState(true);

  // Load historical hooks on mount
  useEffect(() => {
    if (!device || historyLoadedRef.current) return;

    const identifier = mode === Mode.App ? bundle : `pid-${pid}`;
    if (!identifier) return;

    historyLoadedRef.current = true;

    const loadHistory = async () => {
      try {
        const res = await fetch(
          `/api/hooks/${device}/${identifier}?limit=5000`,
        );
        if (res.ok) {
          const data = await res.json();
          if (data.hooks && data.hooks.length > 0) {
            // Convert historical records to HookEntry format
            // Note: records are returned in DESC order, reverse for chronological
            const historicalEntries: HookEntry[] = data.hooks
              .reverse()
              .map(
                (record: {
                  id: number;
                  timestamp: string;
                  payload: HookMessage;
                }) => ({
                  id: idCounterRef.current++,
                  timestamp: new Date(record.timestamp),
                  message: record.payload,
                }),
              );
            setEntries(historicalEntries);
          }
        }
      } catch (e) {
        console.error("Failed to load hook history:", e);
      }
    };

    loadHistory();
  }, [device, bundle, pid, mode]);

  // Resize observer for container
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

  // Throttled flush of pending entries
  const flushPendingEntries = useCallback(() => {
    if (pendingEntriesRef.current.length === 0) return;

    const now = performance.now();
    if (now - lastUpdateRef.current < THROTTLE_MS) {
      // Schedule another flush
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
      // Trim if exceeds max
      if (combined.length > MAX_ENTRIES) {
        return combined.slice(-MAX_ENTRIES);
      }
      return combined;
    });

    // Auto-scroll to bottom
    if (autoScroll && listRef.current) {
      requestAnimationFrame(() => {
        listRef.current?.scrollToRow({
          index: entries.length + newEntries.length - 1,
          align: "end",
        });
      });
    }
  }, [autoScroll, entries.length, listRef]);

  // Handle incoming hook messages
  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const handleHook = (message: HookMessage) => {
      const entry: HookEntry = {
        id: idCounterRef.current++,
        timestamp: new Date(),
        message,
      };

      pendingEntriesRef.current.push(entry);

      // Throttle updates
      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPendingEntries();
        });
      }
    };

    socket.on("hook", handleHook);

    return () => {
      socket.off("hook", handleHook);
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [socket, status, flushPendingEntries]);

  // Handle scroll to detect if user scrolled away from bottom
  const handleRowsRendered = useCallback(
    (visibleRows: { startIndex: number; stopIndex: number }) => {
      // Check if near bottom
      const isNearBottom = visibleRows.stopIndex >= entries.length - 3;
      setAutoScroll(isNearBottom);
    },
    [entries.length],
  );

  const handleClear = useCallback(() => {
    setEntries([]);
    pendingEntriesRef.current = [];
    idCounterRef.current = 0;
  }, []);

  const scrollToLatest = useCallback(() => {
    if (listRef.current && entries.length > 0) {
      listRef.current.scrollToRow({ index: entries.length - 1, align: "end" });
      setAutoScroll(true);
    }
  }, [entries.length]);

  // Memoized row props for the list (only custom props, not ariaAttributes/index/style)
  const rowProps: HookRowProps = useMemo(() => ({ entries, t }), [entries, t]);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b bg-muted/30">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span>
            {entries.length.toLocaleString()} {t("hook_results").toLowerCase()}
          </span>
          {!autoScroll && (
            <Button
              variant="secondary"
              size="sm"
              onClick={scrollToLatest}
              className="h-6 px-2 text-[10px] gap-1"
            >
              <ChevronsDown className="h-3 w-3" />
              {t("scroll_to_latest")}
            </Button>
          )}
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleClear}
          className="h-7 px-2"
        >
          <Trash2 className="h-3.5 w-3.5 mr-1" />
        </Button>
      </div>

      {/* Content */}
      <div ref={containerRef} className="flex-1 min-h-0">
        {entries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            {t("hook_no_results")}
          </div>
        ) : (
          <List
            listRef={listRef}
            style={{ height: listHeight, width: "100%" }}
            rowCount={entries.length}
            rowHeight={ROW_HEIGHT}
            rowProps={rowProps}
            rowComponent={HookRow}
            onRowsRendered={handleRowsRendered}
            overscanCount={20}
          />
        )}
      </div>
    </div>
  );
}
