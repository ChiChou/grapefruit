import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { List, type ListImperativeAPI } from "react-window";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Status, Mode, Platform, useSession } from "@/context/SessionContext";

import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";

interface FlutterHookRecord {
  id: number;
  timestamp: string;
  category: string;
  symbol: string;
  direction: string;
  line: string | null;
  extra?: Record<string, unknown>;
}

interface FlutterChannelExtra {
  platform?: "android" | "ios";
  type?: "method" | "event" | "message";
  dir?: "dart->native" | "native->dart";
  channel?: string;
  method?: string;
  args?: unknown;
  result?: unknown;
  error?: string;
  codec?: "standard" | "json" | "binary" | "unknown";
  truncated?: boolean;
  argsRawHex?: string;
  [key: string]: unknown;
}

interface FlutterChannelEntry {
  id: number;
  timestamp: Date;
  channel: string;
  method: string;
  direction: "dart->native" | "native->dart";
  preview: string;
  message: BaseHookMessage;
  extra: FlutterChannelExtra;
}

type DirectionFilter = "both" | "dart->native" | "native->dart";

const ROW_HEIGHT = 36;
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

function previewValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.length > 96 ? `${value.slice(0, 96)}...` : value;
  if (typeof value === "number" || typeof value === "boolean") return `${value}`;
  if (Array.isArray(value)) return `[${value.length} items]`;
  if (typeof value === "object") {
    try {
      const keys = Object.keys(value as Record<string, unknown>);
      if (keys.length === 0) return "{}";
      return `{${keys.slice(0, 4).join(", ")}${keys.length > 4 ? ", ..." : ""}}`;
    } catch {
      return "{...}";
    }
  }
  return `${value}`;
}

function toEntry(
  message: BaseHookMessage,
  timestamp: Date,
  id: number,
): FlutterChannelEntry | null {
  if (message.category !== "flutter.channel") return null;

  const extra = (message.extra as FlutterChannelExtra | undefined) || {};
  const direction = extra.dir === "native->dart" ? "native->dart" : "dart->native";
  const channel = typeof extra.channel === "string" && extra.channel.length > 0
    ? extra.channel
    : "<unknown>";
  const method = typeof extra.method === "string" && extra.method.length > 0
    ? extra.method
    : "-";

  const previewSource = extra.args ?? extra.result ?? extra.error;
  return {
    id,
    timestamp,
    channel,
    method,
    direction,
    preview: previewValue(previewSource),
    message,
    extra,
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
  entries: FlutterChannelEntry[];
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

  const isSelected = selectedId === entry.id;

  return (
    <button
      type="button"
      style={style}
      onClick={() => onSelect(entry.id)}
      className={`w-full flex items-center gap-2 px-2 border-b text-left text-xs hover:bg-muted/40 ${
        isSelected ? "bg-muted" : ""
      }`}
    >
      <span className="font-mono text-muted-foreground w-24 shrink-0">
        {formatTime(entry.timestamp)}
      </span>
      <Badge
        variant={entry.direction === "dart->native" ? "default" : "secondary"}
        className="h-5 px-1.5 text-[10px] shrink-0"
      >
        {entry.direction === "dart->native" ? "D→N" : "N→D"}
      </Badge>
      <span className="font-mono text-primary truncate w-56 shrink-0" title={entry.channel}>
        {entry.channel}
      </span>
      <span className="font-mono text-xs truncate w-44 shrink-0" title={entry.method}>
        {entry.method}
      </span>
      <span className="text-muted-foreground truncate min-w-0" title={entry.preview}>
        {entry.preview || "--"}
      </span>
    </button>
  );
}

export function FlutterPanel() {
  const { t } = useTranslation();
  const {
    platform,
    mode,
    status,
    socket,
    device,
    bundle,
    pid,
    fruity,
    droid,
    flutterRuntime,
  } = useSession();

  const api = platform === Platform.Fruity ? fruity : droid;
  const identifier = mode === Mode.App ? bundle : `pid-${pid}`;

  const [entries, setEntries] = useState<FlutterChannelEntry[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [channelFilter, setChannelFilter] = useState("");
  const [methodFilter, setMethodFilter] = useState("");
  const [directionFilter, setDirectionFilter] = useState<DirectionFilter>("both");

  const idRef = useRef(1);
  const listRef = useRef<ListImperativeAPI>(null);
  const pendingRef = useRef<FlutterChannelEntry[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastFlushRef = useRef<number>(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [listHeight, setListHeight] = useState(320);

  const { data: hookStatus, refetch: refetchStatus } = useQuery<
    Record<string, { active: boolean; startedAt?: number; dropped?: number }>
  >({
    queryKey: ["flutterHookStatus", platform, device, identifier],
    queryFn: () => api!.flutter.status(),
    enabled:
      status === Status.Ready &&
      !!api &&
      flutterRuntime?.isFlutter === true,
    staleTime: 1000,
    gcTime: 0,
    refetchInterval: 2000,
  });

  const toggleMutation = useMutation({
    mutationFn: async (enable: boolean) => {
      if (!api) return { ok: false };
      if (enable) {
        return api.flutter.start({ group: "channels" });
      }
      return api.flutter.stop({ group: "channels" });
    },
    onSuccess: () => {
      refetchStatus();
    },
  });

  const { data: history } = useQuery<{ hooks: FlutterHookRecord[] }>({
    queryKey: ["flutterHookHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(
        `/api/hooks/${device}/${identifier}?category=flutter.channel&limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load Flutter channel history");
      return res.json();
    },
    enabled:
      status === Status.Ready &&
      !!device &&
      !!identifier &&
      flutterRuntime?.isFlutter === true,
    staleTime: Infinity,
    gcTime: 0,
  });

  useEffect(() => {
    setEntries([]);
    setSelectedId(null);
    idRef.current = 1;
    pendingRef.current = [];
  }, [platform, device, bundle, pid, mode]);

  useEffect(() => {
    if (!history?.hooks) return;

    const next: FlutterChannelEntry[] = [];
    for (const record of history.hooks.slice().reverse()) {
      const entry = toEntry(
        {
          subject: "hook",
          category: record.category,
          symbol: record.symbol,
          dir: record.direction as "enter" | "leave",
          line: record.line || undefined,
          extra: record.extra,
        },
        new Date(record.timestamp),
        idRef.current++,
      );

      if (entry) {
        next.push(entry);
      }
    }

    setEntries(next);
    setSelectedId(next.length > 0 ? next[next.length - 1].id : null);
  }, [history]);

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
      if (merged.length > MAX_ENTRIES) {
        return merged.slice(-MAX_ENTRIES);
      }
      return merged;
    });

    if (incoming.length > 0) {
      const latest = incoming[incoming.length - 1];
      setSelectedId((current) => current ?? latest.id);
      requestAnimationFrame(() => {
        listRef.current?.scrollToRow({
          index: Math.max(0, entries.length + incoming.length - 1),
          align: "end",
        });
      });
    }
  }, [entries.length]);

  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onHook = (message: BaseHookMessage) => {
      if (message.category !== "flutter.channel") return;

      const entry = toEntry(message, new Date(), idRef.current++);
      if (!entry) return;

      pendingRef.current.push(entry);

      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPending();
        });
      }
    };

    socket.on("hook", onHook);

    return () => {
      socket.off("hook", onHook);
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current);
        rafRef.current = null;
      }
    };
  }, [status, socket, flushPending]);

  useEffect(() => {
    if (!containerRef.current) return;

    const observer = new ResizeObserver((resizeEntries) => {
      for (const resizeEntry of resizeEntries) {
        setListHeight(resizeEntry.contentRect.height);
      }
    });

    observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  const filteredEntries = useMemo(() => {
    const channelNeedle = channelFilter.trim().toLowerCase();
    const methodNeedle = methodFilter.trim().toLowerCase();

    return entries.filter((entry) => {
      if (
        directionFilter !== "both" &&
        entry.direction !== directionFilter
      ) {
        return false;
      }

      if (
        channelNeedle.length > 0 &&
        !entry.channel.toLowerCase().includes(channelNeedle)
      ) {
        return false;
      }

      if (
        methodNeedle.length > 0 &&
        !entry.method.toLowerCase().includes(methodNeedle)
      ) {
        return false;
      }

      return true;
    });
  }, [entries, channelFilter, methodFilter, directionFilter]);

  useEffect(() => {
    if (filteredEntries.length === 0) {
      setSelectedId(null);
      return;
    }

    if (!filteredEntries.some((entry) => entry.id === selectedId)) {
      setSelectedId(filteredEntries[filteredEntries.length - 1].id);
    }
  }, [filteredEntries, selectedId]);

  const selectedEntry = useMemo(
    () => filteredEntries.find((entry) => entry.id === selectedId) || null,
    [filteredEntries, selectedId],
  );

  const channelStatus = hookStatus?.channels;
  const isActive = !!channelStatus?.active;

  if (status !== Status.Ready) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("flutter_connect_required")}
      </div>
    );
  }

  if (!flutterRuntime) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("flutter_detecting")}
      </div>
    );
  }

  if (!flutterRuntime.isFlutter) {
    return (
      <div className="h-full p-4 overflow-auto space-y-3">
        <h2 className="text-base font-semibold">{t("flutter_channels")}</h2>
        <div className="rounded-md border p-3 space-y-2">
          <p className="text-sm text-muted-foreground">
            {t("flutter_not_detected")}
          </p>
          {flutterRuntime.hints && flutterRuntime.hints.length > 0 ? (
            <ul className="text-xs text-muted-foreground list-disc pl-4 space-y-1">
              {flutterRuntime.hints.map((hint) => (
                <li key={hint}>{hint}</li>
              ))}
            </ul>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <div className="h-full p-4 flex flex-col gap-3 overflow-hidden">
      <div className="flex items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold">{t("flutter_channels")}</h2>
          <p className="text-xs text-muted-foreground">
            {t("flutter_channels_desc")}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant={isActive ? "default" : "secondary"}>
            {isActive ? t("enabled") : t("disabled")}
          </Badge>
          <Button
            size="sm"
            onClick={() => toggleMutation.mutate(!isActive)}
            disabled={toggleMutation.isPending || !api}
          >
            {isActive ? t("stop") : t("run")}
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge variant="outline">engine: {flutterRuntime.engineModule || "-"}</Badge>
        <Badge variant="outline">app: {flutterRuntime.appModule || "-"}</Badge>
        <Badge variant="outline">
          dropped: {(channelStatus?.dropped ?? 0).toLocaleString()}
        </Badge>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <Input
          value={channelFilter}
          onChange={(event) => setChannelFilter(event.target.value)}
          placeholder={t("flutter_filter_channel")}
        />
        <Input
          value={methodFilter}
          onChange={(event) => setMethodFilter(event.target.value)}
          placeholder={t("flutter_filter_method")}
        />
        <div className="flex items-center">
          <div className="w-full flex items-center gap-1">
            <Button
              type="button"
              variant={directionFilter === "both" ? "default" : "outline"}
              size="sm"
              className="flex-1 text-xs"
              onClick={() => setDirectionFilter("both")}
            >
              {t("flutter_direction_both")}
            </Button>
            <Button
              type="button"
              variant={directionFilter === "dart->native" ? "default" : "outline"}
              size="sm"
              className="flex-1 text-xs"
              onClick={() => setDirectionFilter("dart->native")}
            >
              {t("flutter_direction_d2n")}
            </Button>
            <Button
              type="button"
              variant={directionFilter === "native->dart" ? "default" : "outline"}
              size="sm"
              className="flex-1 text-xs"
              onClick={() => setDirectionFilter("native->dart")}
            >
              {t("flutter_direction_n2d")}
            </Button>
          </div>
        </div>
      </div>

      <div className="flex-1 min-h-0 grid grid-cols-1 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)] gap-3">
        <div className="min-h-0 border rounded-md overflow-hidden">
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

        <div className="min-h-0 border rounded-md overflow-auto p-3 text-xs">
          {!selectedEntry ? (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              {t("flutter_select_event")}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="space-y-1">
                <div><span className="text-muted-foreground">{t("time")}: </span>{formatTime(selectedEntry.timestamp)}</div>
                <div><span className="text-muted-foreground">{t("flutter_channel")}: </span>{selectedEntry.channel}</div>
                <div><span className="text-muted-foreground">{t("method")}: </span>{selectedEntry.method}</div>
                <div><span className="text-muted-foreground">{t("hook_direction")}: </span>{selectedEntry.direction}</div>
                <div><span className="text-muted-foreground">codec: </span>{selectedEntry.extra.codec || "-"}</div>
                <div><span className="text-muted-foreground">truncated: </span>{selectedEntry.extra.truncated ? "yes" : "no"}</div>
              </div>

              <div>
                <div className="text-muted-foreground mb-1">args</div>
                <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                  {formatJson(selectedEntry.extra.args) || "-"}
                </pre>
              </div>

              <div>
                <div className="text-muted-foreground mb-1">result</div>
                <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                  {formatJson(selectedEntry.extra.result) || "-"}
                </pre>
              </div>

              {selectedEntry.extra.argsRawHex ? (
                <div>
                  <div className="text-muted-foreground mb-1">argsRawHex</div>
                  <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-32 whitespace-pre-wrap break-all">
                    {selectedEntry.extra.argsRawHex}
                  </pre>
                </div>
              ) : null}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
