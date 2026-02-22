import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { type ColumnDef } from "@tanstack/react-table";

import { Trash2, Play, Square, Loader2, ChevronsDown } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { LogTable } from "@/components/shared/LogTable";
import { Status, Platform, useSession } from "@/context/SessionContext";
import { useLogStream } from "@/hooks/useLogStream";
import { toTime } from "@/lib/format";

const TAP_ID = "flutter";

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

function toEntry(event: FlutterEvent, timestamp: Date, id: number): FlutterEntry {
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

function preview(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string")
    return value.length > 96 ? `${value.slice(0, 96)}...` : value;
  if (typeof value === "number" || typeof value === "boolean")
    return `${value}`;
  if (Array.isArray(value)) return `[${value.length} items]`;
  if (typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) return "{}";
    return `{${keys.slice(0, 4).join(", ")}${keys.length > 4 ? ", ..." : ""}}`;
  }
  return `${value}`;
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

const mapHistory = (record: Record<string, unknown>, id: number): FlutterEntry => {
  const data = record.data as Record<string, unknown> | undefined;
  const event: FlutterEvent = {
    type: (record.type as FlutterEvent["type"]) ?? "method",
    dir: (record.direction as FlutterEvent["dir"]) ?? "dart",
    channel: record.channel as string,
    ...data,
  };
  return toEntry(event, new Date(record.timestamp as string), id);
};

const mapSocket = (id: number, ...args: unknown[]): FlutterEntry =>
  toEntry(args[0] as FlutterEvent, new Date(), id);

const columns: ColumnDef<FlutterEntry>[] = [
  {
    id: "timestamp",
    header: "Time",
    size: 96,
    cell: ({ row }) => (
      <span className="font-mono text-muted-foreground">
        {toTime(row.original.timestamp)}
      </span>
    ),
  },
  {
    id: "direction",
    header: "Dir",
    size: 80,
    cell: ({ row }) => (
      <Badge
        variant={row.original.direction === "dart" ? "default" : "secondary"}
        className="h-5 px-1.5 text-[10px]"
      >
        {row.original.direction === "dart" ? "\u2192 Native" : "\u2192 Dart"}
      </Badge>
    ),
  },
  {
    accessorKey: "channel",
    header: "Channel",
    size: 240,
    cell: ({ getValue }) => (
      <span className="font-mono truncate" title={getValue<string>()}>
        {getValue<string>()}
      </span>
    ),
  },
  {
    accessorKey: "method",
    header: "Method",
    size: 180,
    cell: ({ getValue }) => (
      <span className="font-mono truncate" title={getValue<string>()}>
        {getValue<string>()}
      </span>
    ),
  },
  {
    id: "args",
    header: "Args",
    size: 200,
    cell: ({ row }) => {
      const text = preview(row.original.event.args);
      return (
        <span className="text-muted-foreground truncate" title={text}>
          {text || "--"}
        </span>
      );
    },
  },
];

export function FlutterMethodChannelsTab() {
  const { t } = useTranslation();
  const { platform, status, device, identifier, fruity, droid } = useSession();

  const api = platform === Platform.Fruity ? fruity : droid;

  const [isActive, setIsActive] = useState<boolean | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [showDart, setShowDart] = useState(true);
  const [showNative, setShowNative] = useState(true);
  const tableContainerRef = useRef<HTMLDivElement>(null);

  // Check if flutter is available
  const { data: flutterAvailable, isLoading: flutterLoading } = useQuery({
    queryKey: ["flutterAvailable", platform, device],
    queryFn: () => api!.taps.available(TAP_ID),
    enabled: status === Status.Ready && !!api,
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  });

  const {
    entries,
    selectedId,
    setSelectedId,
    clear,
    clearMutation,
  } = useLogStream<FlutterEntry>({
    event: "flutter",
    path: "history/flutter",
    key: "logs",
    fromRecord: mapHistory,
    fromEvent: mapSocket,
    enabled: !!flutterAvailable,
  });

  // Sync initial active state from agent
  const { data: initialActive } = useQuery({
    queryKey: ["flutterActive", platform, device],
    queryFn: () => api!.taps.active(TAP_ID),
    enabled: status === Status.Ready && !!api,
  });

  useEffect(() => {
    if (initialActive !== undefined && isActive === null)
      setIsActive(initialActive);
  }, [initialActive, isActive]);

  // Reset active state on session change
  useEffect(() => {
    setIsActive(false);
  }, [platform, device, identifier]);

  // Toggle start/stop
  const toggleMutation = useMutation({
    mutationFn: async (enable: boolean) => {
      if (!api) return;
      if (enable) {
        await api.taps.start(TAP_ID);
      } else {
        await api.taps.stop(TAP_ID);
      }
    },
    onSuccess: (_, enable) => {
      setIsActive(enable);
    },
  });

  // Filter entries
  const filteredEntries = useMemo(() => {
    const q = searchFilter.trim().toLowerCase();
    return entries.filter((e) => {
      if (e.direction === "dart" && !showDart) return false;
      if (e.direction === "native" && !showNative) return false;
      if (
        q &&
        !e.channel.toLowerCase().includes(q) &&
        !e.method.toLowerCase().includes(q)
      )
        return false;
      return true;
    });
  }, [entries, searchFilter, showDart, showNative]);

  const selectedEntry = useMemo(
    () => filteredEntries.find((e) => e.id === selectedId) ?? null,
    [filteredEntries, selectedId],
  );

  const notReady =
    status !== Status.Ready || flutterLoading || !flutterAvailable;

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="flutter-split"
    >
      {/* Left: toolbar + event list */}
      <ResizablePanel defaultSize="65%" minSize="30%">
        <div className="h-full flex flex-col overflow-hidden">
          {/* Toolbar */}
          <div className="flex items-center gap-2 p-2 border-b shrink-0">
            {isActive ? (
              <Button
                variant="outline"
                size="sm"
                className="h-8 px-2.5 text-xs text-red-500 hover:text-red-600"
                onClick={() => toggleMutation.mutate(false)}
                disabled={notReady || toggleMutation.isPending || !api}
              >
                {toggleMutation.isPending ? (
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
                onClick={() => toggleMutation.mutate(true)}
                disabled={notReady || toggleMutation.isPending || !api}
              >
                {toggleMutation.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Start
              </Button>
            )}
            <Input
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder={t("search")}
              className="h-8 max-w-xs"
            />
            <label className="flex items-center gap-1.5 text-sm shrink-0">
              <Checkbox checked={showDart} onCheckedChange={setShowDart} />
              {"\u2192 Native"}
            </label>
            <label className="flex items-center gap-1.5 text-sm shrink-0">
              <Checkbox checked={showNative} onCheckedChange={setShowNative} />
              {"\u2192 Dart"}
            </label>
            <span className="text-xs text-muted-foreground ml-auto">
              {filteredEntries.length} event
              {filteredEntries.length !== 1 ? "s" : ""}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() =>
                tableContainerRef.current?.scrollTo({
                  top: tableContainerRef.current.scrollHeight,
                  behavior: "smooth",
                })
              }
            >
              <ChevronsDown className="w-4 h-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-red-500 hover:text-red-600 hover:bg-red-100 dark:hover:bg-red-950/30"
              onClick={clear}
              disabled={clearMutation.isPending || entries.length === 0}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>

          {/* Virtualized table */}
          <LogTable
            data={filteredEntries}
            columns={columns}
            selectedId={selectedId}
            onSelect={setSelectedId}
            scrollRef={tableContainerRef}
          />
        </div>
      </ResizablePanel>

      <ResizableHandle />

      {/* Right: detail panel */}
      <ResizablePanel defaultSize="35%" minSize="15%">
        <div className="h-full overflow-auto p-3 text-xs">
          {!selectedEntry ? (
            <div className="h-full flex items-center justify-center text-muted-foreground">
              {t("flutter_select_event")}
            </div>
          ) : (
            <div className="space-y-3">
              <div className="space-y-1">
                <div>
                  <span className="text-muted-foreground">{t("time")}: </span>
                  {toTime(selectedEntry.timestamp)}
                </div>
                <div>
                  <span className="text-muted-foreground">
                    {t("flutter_channel")}:{" "}
                  </span>
                  {selectedEntry.channel}
                </div>
                <div>
                  <span className="text-muted-foreground">{t("method")}: </span>
                  {selectedEntry.method}
                </div>
                <div>
                  <span className="text-muted-foreground">
                    {t("hook_direction")}:{" "}
                  </span>
                  {selectedEntry.direction === "dart"
                    ? "\u2192 Native"
                    : "\u2192 Dart"}
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
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
