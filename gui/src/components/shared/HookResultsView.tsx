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
  Database,
  Trash2,
  ChevronsDown,
  Clipboard,
  Fingerprint,
  Smartphone,
  FolderOpen,
  Copy,
  Check,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { useLogStream } from "@/hooks/useLogStream";
import { toTime } from "@/lib/format";

import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";

interface HookEntry {
  id: number;
  timestamp: Date;
  message: BaseHookMessage;
}

const ROW_HEIGHT = 32;

function CategoryIcon({ category }: { category: string }) {
  switch (category) {
    case "sql":
      return <Database className="h-3.5 w-3.5" />;
    case "pasteboard":
      return <Clipboard className="h-3.5 w-3.5" />;
    case "biometric":
      return <Fingerprint className="h-3.5 w-3.5" />;
    case "deviceid":
      return <Smartphone className="h-3.5 w-3.5" />;
    case "fileops":
      return <FolderOpen className="h-3.5 w-3.5" />;
    default:
      return <Layers className="h-3.5 w-3.5" />;
  }
}

function formatSummary(message: BaseHookMessage): string {
  return message.line || "";
}

function SummaryPopover({ summary }: { summary: string }) {
  const [copied, setCopied] = useState(false);

  if (!summary) {
    return <span className="text-muted-foreground/30">--</span>;
  }

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(summary);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (e) {
      console.error("Failed to copy:", e);
    }
  };

  return (
    <Popover>
      <PopoverTrigger nativeButton={false} render={<span
          className="font-mono text-muted-foreground truncate flex-1 min-w-0 cursor-pointer hover:text-foreground"
          title={summary}
        />}>
          {summary}
      </PopoverTrigger>
      <PopoverContent className="w-[500px] p-0" align="start">
        <div className="flex items-center justify-end p-2 border-b">
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs gap-1"
            onClick={handleCopy}
          >
            {copied ? (
              <>
                <Check className="h-3 w-3" />
                Copied
              </>
            ) : (
              <>
                <Copy className="h-3 w-3" />
                Copy
              </>
            )}
          </Button>
        </div>
        <ScrollArea className="max-h-[300px]">
          <div className="p-3 font-mono text-xs whitespace-pre-wrap break-all">
            {summary}
          </div>
        </ScrollArea>
      </PopoverContent>
    </Popover>
  );
}

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
      <PopoverTrigger render={<Button variant="outline" size="sm" className="h-6 px-1.5" />}>
          <Layers className="h-3 w-3" />
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

interface HookRowProps {
  entries: HookEntry[];
  t: (key: string) => string;
}

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
      <span className="text-muted-foreground font-mono w-24 shrink-0">
        {toTime(timestamp)}
      </span>
      <Badge
        variant="outline"
        className="flex items-center gap-1 h-5 px-1.5 shrink-0"
      >
        <CategoryIcon category={message.category} />
        <span className="text-[10px]">{message.category}</span>
      </Badge>
      <Badge
        variant={message.dir === "enter" ? "default" : "secondary"}
        className="h-5 px-1.5 text-[10px] shrink-0"
      >
        <ChevronRight
          className={`h-3 w-3 ${message.dir === "leave" ? "rotate-180" : ""}`}
        />
      </Badge>
      <span
        className="font-mono text-primary truncate w-48 shrink-0"
        title={message.symbol}
      >
        {message.symbol}
      </span>
      <SummaryPopover summary={formatSummary(message)} />
      <div className="shrink-0">
        <StackTracePopover bt={message.backtrace} t={t} />
      </div>
    </div>
  );
}

const mapHistory = (record: Record<string, unknown>, id: number): HookEntry | null => {
  if (record.category === "crypto") return null;
  return {
    id,
    timestamp: new Date(record.timestamp as string),
    message: {
      subject: "hook",
      category: record.category as string,
      symbol: record.symbol as string,
      dir: record.direction as "enter" | "leave",
      line: (record.line as string) ?? undefined,
      extra: record.extra as Record<string, unknown> | undefined,
    },
  };
};

const mapHistoryNonNull = (record: Record<string, unknown>, id: number): HookEntry =>
  mapHistory(record, id)!;

const mapSocket = (id: number, ...args: unknown[]): HookEntry | null => {
  const message = args[0] as BaseHookMessage;
  if (message.category === "crypto") return null;
  return { id, timestamp: new Date(), message };
};

export function HookResultsView() {
  const { t } = useTranslation();
  const listRef = useRef<ListImperativeAPI>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [listHeight, setListHeight] = useState(300);
  const [autoScroll, setAutoScroll] = useState(true);

  const {
    entries,
    clear,
  } = useLogStream<HookEntry>({
    event: "hook",
    path: "hooks",
    key: "hooks",
    fromRecord: mapHistoryNonNull,
    fromEvent: mapSocket,
    max: 10000,
  });

  // Filter out null entries from mapHistory (crypto category)
  const filteredEntries = useMemo(
    () => entries.filter((e): e is HookEntry => e !== null),
    [entries],
  );

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

  // Auto-scroll when new entries arrive
  useEffect(() => {
    if (autoScroll && listRef.current && filteredEntries.length > 0) {
      requestAnimationFrame(() => {
        listRef.current?.scrollToRow({
          index: filteredEntries.length - 1,
          align: "end",
        });
      });
    }
  }, [filteredEntries.length, autoScroll]);

  const handleRowsRendered = useCallback(
    (visibleRows: { startIndex: number; stopIndex: number }) => {
      const isNearBottom = visibleRows.stopIndex >= filteredEntries.length - 3;
      setAutoScroll((prev) => (prev === isNearBottom ? prev : isNearBottom));
    },
    [filteredEntries.length],
  );

  const scrollToLatest = useCallback(() => {
    if (listRef.current && filteredEntries.length > 0) {
      listRef.current.scrollToRow({ index: filteredEntries.length - 1, align: "end" });
      setAutoScroll(true);
    }
  }, [filteredEntries.length]);

  const rowProps: HookRowProps = useMemo(() => ({ entries: filteredEntries, t }), [filteredEntries, t]);
  const listStyle = useMemo(() => ({ height: listHeight, width: "100%" as const }), [listHeight]);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-3 py-2 border-b bg-muted/30">
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <span>
            {filteredEntries.length.toLocaleString()} {t("hook_results").toLowerCase()}
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
          onClick={clear}
          className="h-7 px-2"
        >
          <Trash2 className="h-3.5 w-3.5 mr-1" />
        </Button>
      </div>

      {/* Content */}
      <div ref={containerRef} className="flex-1 min-h-0">
        {filteredEntries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            {t("hook_no_results")}
          </div>
        ) : (
          <List
            listRef={listRef}
            style={listStyle}
            rowCount={filteredEntries.length}
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
