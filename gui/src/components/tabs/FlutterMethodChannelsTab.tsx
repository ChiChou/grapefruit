import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";

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
import { Status, Platform, useSession } from "@/context/SessionContext";

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

const MAX_ENTRIES = 8000;
const THROTTLE_MS = 100;
const ROW_HEIGHT = 32;

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

const columns: ColumnDef<FlutterEntry>[] = [
  {
    id: "timestamp",
    header: "Time",
    size: 96,
    cell: ({ row }) => (
      <span className="font-mono text-muted-foreground">
        {formatTime(row.original.timestamp)}
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
  const pendingRef = useRef<FlutterEntry[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tableContainerRef = useRef<HTMLDivElement>(null);

  // Check if flutter is available
  const {
    data: flutterAvailable,
    isLoading: flutterLoading,
  } = useQuery({
    queryKey: ["flutterAvailable", platform, device],
    queryFn: () => api!.taps.available(TAP_ID),
    enabled: status === Status.Ready && !!api,
    staleTime: Infinity,
    gcTime: 0,
    retry: false,
  });

  // Sync initial active state from agent
  const { data: initialActive } = useQuery({
    queryKey: ["flutterActive", platform, device],
    queryFn: () => api!.taps.active(TAP_ID),
    enabled: status === Status.Ready && !!api,
  });

  useEffect(() => {
    if (initialActive !== undefined) setIsActive(initialActive);
  }, [initialActive]);

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

  // Clear history
  const clearMutation = useMutation({
    mutationFn: async () => {
      if (!device || !identifier) return;
      const res = await fetch(`/api/history/flutter/${device}/${identifier}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to clear history");
    },
    onSuccess: () => {
      setEntries([]);
      setSelectedId(null);
      idRef.current = 1;
      pendingRef.current = [];
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

  // Flush pending entries
  const flushPending = useCallback(() => {
    timerRef.current = null;
    if (pendingRef.current.length === 0) return;

    const incoming = pendingRef.current;
    pendingRef.current = [];

    setEntries((prev) => {
      const merged = [...prev, ...incoming];
      return merged.length > MAX_ENTRIES ? merged.slice(-MAX_ENTRIES) : merged;
    });
  }, []);

  // Listen for live hook events
  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onFlutter = (message: Record<string, unknown>) => {
      const entry = toEntry(message as unknown as FlutterEvent, new Date(), idRef.current++);
      pendingRef.current.push(entry);
      if (!timerRef.current) {
        timerRef.current = setTimeout(flushPending, THROTTLE_MS);
      }
    };

    socket.on("flutter", onFlutter);
    return () => {
      socket.off("flutter", onFlutter);
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [status, socket, flushPending]);

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

  const table = useReactTable({
    data: filteredEntries,
    columns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => String(row.id),
  });

  const { rows } = table.getRowModel();

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => tableContainerRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();

  const notReady = status !== Status.Ready || flutterLoading || !flutterAvailable;

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
                {toggleMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Square className="w-3.5 h-3.5" />}
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
                {toggleMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
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
              {filteredEntries.length} event{filteredEntries.length !== 1 ? "s" : ""}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() => tableContainerRef.current?.scrollTo({ top: tableContainerRef.current.scrollHeight, behavior: "smooth" })}
            >
              <ChevronsDown className="w-4 h-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-red-500 hover:text-red-600 hover:bg-red-100 dark:hover:bg-red-950/30"
              onClick={() => clearMutation.mutate()}
              disabled={clearMutation.isPending || entries.length === 0}
            >
              <Trash2 className="w-4 h-4" />
            </Button>
          </div>

          {/* Virtualized table */}
          <div ref={tableContainerRef} className="flex-1 overflow-auto">
            <table className="w-full text-xs border-collapse">
              <thead className="sticky top-0 bg-background z-10">
                {table.getHeaderGroups().map((headerGroup) => (
                  <tr key={headerGroup.id} className="border-b">
                    {headerGroup.headers.map((header) => (
                      <th
                        key={header.id}
                        className="text-left font-medium p-2 text-muted-foreground"
                        style={{ width: header.getSize() }}
                      >
                        {flexRender(header.column.columnDef.header, header.getContext())}
                      </th>
                    ))}
                  </tr>
                ))}
              </thead>
              <tbody>
                {virtualRows.length > 0 && virtualRows[0].start > 0 && (
                  <tr>
                    <td colSpan={columns.length} style={{ height: virtualRows[0].start }} />
                  </tr>
                )}
                {virtualRows.map((virtualRow) => {
                  const row = rows[virtualRow.index];
                  return (
                    <tr
                      key={row.id}
                      className={`border-b cursor-pointer hover:bg-muted/50 ${
                        selectedId === row.original.id ? "bg-accent" : ""
                      }`}
                      style={{ height: virtualRow.size }}
                      onClick={() =>
                        setSelectedId(selectedId === row.original.id ? null : row.original.id)
                      }
                    >
                      {row.getVisibleCells().map((cell) => (
                        <td
                          key={cell.id}
                          className="p-2 truncate"
                          style={{ width: cell.column.getSize(), maxWidth: cell.column.getSize() }}
                        >
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  );
                })}
                {virtualRows.length > 0 && (
                  <tr>
                    <td
                      colSpan={columns.length}
                      style={{ height: totalSize - (virtualRows[virtualRows.length - 1]?.end ?? 0) }}
                    />
                  </tr>
                )}
              </tbody>
            </table>
          </div>
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
