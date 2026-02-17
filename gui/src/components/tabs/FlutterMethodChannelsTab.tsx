import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { List, type ListImperativeAPI } from "react-window";

import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Status, Platform, useSession } from "@/context/SessionContext";

interface FlutterEvent {
  type: "method" | "event" | "message";
  dir: "native" | "dart";
  channel: string;
  method?: string;
  args?: unknown;
  result?: unknown;
}

interface FlutterEntry {
  id: number;
  timestamp: Date;
  channel: string;
  method: string;
  direction: "dart" | "native";
  type: "method" | "event" | "message";
  event: FlutterEvent;
}


const ROW_HEIGHT = 32;
const MAX_ENTRIES = 8000;
const THROTTLE_MS = 100;

function formatTime(date: Date): string {
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    fractionalSecondDigits: 3,
  });
}

function preview(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string")
    return value.length > 96 ? `${value.slice(0, 96)}...` : value;
  if (typeof value === "number" || typeof value === "boolean") return `${value}`;
  if (Array.isArray(value)) return `[${value.length} items]`;
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) return "{}";
    return `{${keys.slice(0, 4).join(", ")}${keys.length > 4 ? ", ..." : ""}}`;
  }
  return `${value}`;
}

function toEntry(
  event: FlutterEvent,
  timestamp: Date,
  id: number,
): FlutterEntry {
  return {
    id,
    timestamp,
    channel: event.channel ?? "<unknown>",
    method: event.method ?? "-",
    direction: event.dir === "native" ? "native" : "dart",
    type: event.type ?? "method",
    event,
  };
}

function formatJson(value: unknown): string {
  if (value === undefined) return "";
  if (typeof value === "string") return value;
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return `${value}`;
  }
}

interface FlutterRowProps {
  entries: FlutterEntry[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

function FlutterRow(
  props: {
    ariaAttributes: {
      "aria-posinset": number;
      "aria-setsize": number;
      role: "listitem";
    };
    index: number;
    style: CSSProperties;
  } & FlutterRowProps,
) {
  const { index, style, entries, selectedId, onSelect } = props;
  const entry = entries[index];
  if (!entry) return null;

  return (
    <button
      type="button"
      style={style}
      onClick={() => onSelect(entry.id)}
      className={`w-full flex items-center gap-2 px-2 border-b text-left text-xs hover:bg-muted/40 ${
        selectedId === entry.id ? "bg-muted" : ""
      }`}
    >
      <span className="font-mono text-muted-foreground w-24 shrink-0">
        {formatTime(entry.timestamp)}
      </span>
      <Badge
        variant={entry.direction === "dart" ? "default" : "secondary"}
        className="h-5 px-1.5 text-[10px] shrink-0"
      >
        {entry.direction === "dart" ? "D\u2192N" : "N\u2192D"}
      </Badge>
      <span
        className="font-mono text-primary truncate w-56 shrink-0"
        title={entry.channel}
      >
        {entry.channel}
      </span>
      <span
        className="font-mono text-xs truncate w-44 shrink-0"
        title={entry.method}
      >
        {entry.method}
      </span>
      <span
        className="text-muted-foreground truncate min-w-0"
        title={preview(entry.event.args)}
      >
        {preview(entry.event.args) || "--"}
      </span>
    </button>
  );
}

export function FlutterMethodChannelsTab() {
  const { t } = useTranslation();
  const { platform, status, socket, device, identifier, fruity, droid } =
    useSession();

  const api = platform === Platform.Fruity ? fruity : droid;

  const [isActive, setIsActive] = useState(false);
  const [entries, setEntries] = useState<FlutterEntry[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [showDart, setShowDart] = useState(true);
  const [showNative, setShowNative] = useState(true);

  const idRef = useRef(1);
  const listRef = useRef<ListImperativeAPI>(null);
  const pendingRef = useRef<FlutterEntry[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastFlushRef = useRef(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [listHeight, setListHeight] = useState(320);

  // Check if flutter is available
  const {
    data: flutterAvailable,
    isLoading: flutterLoading,
  } = useQuery({
    queryKey: ["flutterAvailable", platform, device],
    queryFn: async () => !!(await api!.flutter.available()),
    enabled: status === Status.Ready && !!api,
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  });

  // Toggle start/stop
  const toggleMutation = useMutation({
    mutationFn: async (enable: boolean) => {
      if (!api) return;
      if (enable) {
        api.flutter.start();
      } else {
        api.flutter.stop();
      }
    },
    onSuccess: (_, enable) => {
      setIsActive(enable);
    },
  });

  // Load history
  const { data: history } = useQuery<{
    logs: {
      id: number;
      timestamp: string;
      type: string;
      direction: string;
      channel: string;
      data?: Record<string, unknown>;
    }[];
  }>({
    queryKey: ["flutterHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(
        `/api/history/flutter/${device}/${identifier}?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load Flutter channel history");
      return res.json();
    },
    enabled:
      status === Status.Ready &&
      !!device &&
      !!identifier &&
      !!flutterAvailable,
    staleTime: Infinity,
    gcTime: 0,
  });

  // Reset on session change
  useEffect(() => {
    setEntries([]);
    setSelectedId(null);
    setIsActive(false);
    idRef.current = 1;
    pendingRef.current = [];
  }, [platform, device, identifier]);

  // Load historical entries
  useEffect(() => {
    if (!history?.logs) return;

    const next: FlutterEntry[] = [];
    for (const record of [...history.logs].reverse()) {
      const event: FlutterEvent = {
        type: (record.type as FlutterEvent["type"]) ?? "method",
        dir: (record.direction as FlutterEvent["dir"]) ?? "dart",
        channel: record.channel,
        ...record.data,
      };
      next.push(toEntry(event, new Date(record.timestamp), idRef.current++));
    }

    setEntries(next);
  }, [history]);

  // Flush pending entries with throttling
  const flushPending = useCallback(() => {
    if (pendingRef.current.length === 0) return;

    const now = performance.now();
    if (now - lastFlushRef.current < THROTTLE_MS) {
      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPending();
        });
      }
      return;
    }

    lastFlushRef.current = now;
    const incoming = pendingRef.current;
    pendingRef.current = [];

    setEntries((prev) => {
      const merged = [...prev, ...incoming];
      return merged.length > MAX_ENTRIES ? merged.slice(-MAX_ENTRIES) : merged;
    });

    requestAnimationFrame(() => {
      listRef.current?.scrollToRow({
        index: Math.max(0, entries.length + incoming.length - 1),
        align: "end",
      });
    });
  }, [entries.length]);

  // Listen for live hook events
  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onFlutter = (message: Record<string, unknown>) => {
      const entry = toEntry(message as unknown as FlutterEvent, new Date(), idRef.current++);

      pendingRef.current.push(entry);
      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPending();
        });
      }
    };

    socket.on("flutter", onFlutter);
    return () => {
      socket.off("flutter", onFlutter);
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [status, socket, flushPending]);

  // Observe container size
  useEffect(() => {
    if (!containerRef.current) return;
    const observer = new ResizeObserver((es) => {
      for (const e of es) setListHeight(e.contentRect.height);
    });
    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  // Filter entries
  const filteredEntries = useMemo(() => {
    const q = searchFilter.trim().toLowerCase();
    return entries.filter((e) => {
      if (e.direction === "dart" && !showDart) return false;
      if (e.direction === "native" && !showNative) return false;
      if (q && !e.channel.toLowerCase().includes(q) && !e.method.toLowerCase().includes(q))
        return false;
      return true;
    });
  }, [entries, searchFilter, showDart, showNative]);

  const selectedEntry = useMemo(
    () => filteredEntries.find((e) => e.id === selectedId) ?? null,
    [filteredEntries, selectedId],
  );

  if (status !== Status.Ready) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("flutter_waiting")}
      </div>
    );
  }

  if (flutterLoading) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("flutter_detecting")}
      </div>
    );
  }

  if (!flutterAvailable) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("flutter_not_detected")}
      </div>
    );
  }

  return (
    <div className="h-full p-4 flex flex-col gap-3 overflow-hidden">
      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <label className="flex items-center gap-2 text-sm shrink-0">
          <Switch
            checked={isActive}
            onCheckedChange={(checked) => toggleMutation.mutate(checked)}
            disabled={toggleMutation.isPending || !api}
          />
          {t("flutter_capturing")}
        </label>
        <Input
          value={searchFilter}
          onChange={(e) => setSearchFilter(e.target.value)}
          placeholder={t("search")}
          className="max-w-xs"
        />
        <label className="flex items-center gap-1.5 text-sm shrink-0">
          <Checkbox checked={showDart} onCheckedChange={setShowDart} />
          {t("flutter_direction_d2n")}
        </label>
        <label className="flex items-center gap-1.5 text-sm shrink-0">
          <Checkbox checked={showNative} onCheckedChange={setShowNative} />
          {t("flutter_direction_n2d")}
        </label>
      </div>

      {/* Content */}
      <div className="flex-1 min-h-0 grid grid-cols-1 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)] gap-3">
        {/* Event list */}
        <div className="h-full min-h-0 border rounded-md overflow-hidden">
          <div className="grid grid-cols-[96px_64px_224px_176px_minmax(0,1fr)] gap-2 px-2 py-1 border-b bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground">
            <span>{t("hook_timestamp")}</span>
            <span>{t("hook_direction")}</span>
            <span>{t("flutter_channel")}</span>
            <span>{t("method")}</span>
            <span>{t("args")}</span>
          </div>

          <div ref={containerRef} className="h-[calc(100%-30px)] min-h-0">
            {filteredEntries.length === 0 ? (
              <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                {t("flutter_no_events")}
              </div>
            ) : (
              <List
                listRef={listRef}
                style={{ height: listHeight, width: "100%" }}
                rowCount={filteredEntries.length}
                rowHeight={ROW_HEIGHT}
                rowComponent={FlutterRow}
                rowProps={{
                  entries: filteredEntries,
                  selectedId,
                  onSelect: setSelectedId,
                }}
                overscanCount={20}
              />
            )}
          </div>
        </div>

        {/* Detail panel */}
        <div className="min-h-0 border rounded-md overflow-auto p-3 text-xs">
          {!selectedEntry ? (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              {t("flutter_select_event")}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="space-y-1">
                <div>
                  <span className="text-muted-foreground">{t("time")}: </span>
                  {formatTime(selectedEntry.timestamp)}
                </div>
                <div>
                  <span className="text-muted-foreground">
                    {t("flutter_channel")}:{" "}
                  </span>
                  {selectedEntry.channel}
                </div>
                <div>
                  <span className="text-muted-foreground">
                    {t("method")}:{" "}
                  </span>
                  {selectedEntry.method}
                </div>
                <div>
                  <span className="text-muted-foreground">
                    {t("hook_direction")}:{" "}
                  </span>
                  {selectedEntry.direction === "dart"
                    ? "Dart \u2192 Native"
                    : "Native \u2192 Dart"}
                </div>
              </div>

              <div>
                <div className="text-muted-foreground mb-1">args</div>
                <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                  {formatJson(selectedEntry.event.args) || "-"}
                </pre>
              </div>

              <div>
                <div className="text-muted-foreground mb-1">result</div>
                <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                  {formatJson(selectedEntry.event.result) || "-"}
                </pre>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
