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
import { Input } from "@/components/ui/input";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { Status, useSession } from "@/context/SessionContext";
import type { JNIEvent, JNILog } from "@agent/droid/observers/jni";

/** Flattened event shape for display (union of live + historical fields). */
interface JNIDisplayEvent {
  type: string;
  method: string;
  callType: string;
  threadId: number;
  args: string[];
  ret: string;
  backtrace?: string[];
  library?: string | null;
}

interface JNIEntry {
  id: number;
  timestamp: Date;
  event: JNIDisplayEvent;
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

function argsPreview(args: string[]): string {
  if (!args || args.length === 0) return "";
  const joined = args.join(", ");
  return joined.length > 80 ? `${joined.slice(0, 80)}...` : joined;
}

function toEntry(
  event: JNIDisplayEvent,
  timestamp: Date,
  id: number,
): JNIEntry {
  return { id, timestamp, event };
}

const columns: ColumnDef<JNIEntry>[] = [
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
    id: "tid",
    header: "TID",
    size: 48,
    cell: ({ row }) => (
      <span className="font-mono text-muted-foreground text-center">
        {row.original.event.threadId ?? "-"}
      </span>
    ),
  },
  {
    id: "type",
    header: "Type",
    size: 64,
    cell: ({ row }) => {
      const { event } = row.original;
      const isLoad = event.type === "load";
      return (
        <Badge
          variant={
            isLoad
              ? "outline"
              : event.callType === "JavaVM"
                ? "secondary"
                : "default"
          }
          className="h-5 px-1.5 text-[10px]"
        >
          {isLoad ? "load" : event.callType}
        </Badge>
      );
    },
  },
  {
    id: "method",
    header: "Method",
    size: 220,
    cell: ({ row }) => (
      <span className="font-mono text-primary truncate" title={row.original.event.method}>
        {row.original.event.method}
      </span>
    ),
  },
  {
    id: "args",
    header: "Args",
    size: 200,
    cell: ({ row }) => {
      const text = argsPreview(row.original.event.args);
      return (
        <span className="font-mono text-muted-foreground truncate" title={text}>
          {text || "--"}
        </span>
      );
    },
  },
];

export function JNITab() {
  const { t } = useTranslation();
  const { status, socket, device, identifier, droid } = useSession();

  const [isActive, setIsActive] = useState(false);
  const [entries, setEntries] = useState<JNIEntry[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [searchFilter, setSearchFilter] = useState("");

  const idRef = useRef(1);
  const pendingRef = useRef<JNIEntry[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tableContainerRef = useRef<HTMLDivElement>(null);

  // Toggle start/stop
  const toggleMutation = useMutation({
    mutationFn: async (enable: boolean) => {
      if (!droid) return;
      if (enable) {
        await droid.jni.start();
      } else {
        await droid.jni.stop();
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
      const res = await fetch(`/api/history/jni/${device}/${identifier}`, {
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
  const { data: history } = useQuery<{ logs: JNILog[] }>({
    queryKey: ["jniHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(
        `/api/history/jni/${device}/${identifier}?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load JNI trace history");
      return res.json();
    },
    enabled: status === Status.Ready && !!device && !!identifier,
    staleTime: Infinity,
  });

  // Reset on session change
  useEffect(() => {
    setEntries([]);
    setSelectedId(null);
    setIsActive(false);
    idRef.current = 1;
    pendingRef.current = [];
  }, [device, identifier]);

  // Load historical entries
  useEffect(() => {
    if (!history?.logs) return;

    const next: JNIEntry[] = [];
    for (const record of [...history.logs].reverse()) {
      const event: JNIDisplayEvent = {
        type: record.type ?? "trace",
        method: record.method,
        callType: record.callType ?? "JNIEnv",
        threadId: record.threadId ?? 0,
        args: record.args ?? [],
        ret: record.ret ?? "",
        backtrace: record.backtrace,
        library: record.library,
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

  // Listen for live trace events
  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onJNI = (raw: JNIEvent) => {
      const event: JNIDisplayEvent = {
        type: raw.type,
        method: raw.method,
        callType: raw.callType,
        threadId: raw.threadId,
        args: raw.args,
        ret: raw.ret,
        library: raw.type === "load" ? raw.library : undefined,
      };
      const entry = toEntry(event, new Date(), idRef.current++);
      pendingRef.current.push(entry);
      if (!timerRef.current) {
        timerRef.current = setTimeout(flushPending, THROTTLE_MS);
      }
    };

    socket.on("jni", onJNI);
    return () => {
      socket.off("jni", onJNI);
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [status, socket, flushPending]);

  // Filter entries
  const filteredEntries = useMemo(() => {
    const q = searchFilter.trim().toLowerCase();
    if (!q) return entries;
    return entries.filter(
      (e) =>
        e.event.method.toLowerCase().includes(q) ||
        e.event.args.some((a) => a.toLowerCase().includes(q)) ||
        (e.event.library?.toLowerCase().includes(q) ?? false),
    );
  }, [entries, searchFilter]);

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

  const notReady = status !== Status.Ready;

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="jni-split"
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
                disabled={notReady || toggleMutation.isPending || !droid}
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
                disabled={notReady || toggleMutation.isPending || !droid}
              >
                {toggleMutation.isPending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                Start
              </Button>
            )}
            <Input
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter..."
              className="h-8 max-w-xs"
            />
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
              <Trash2 className="h-4 w-4" />
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
              Select an event to view details
            </div>
          ) : (
            <div className="space-y-3">
              <div className="space-y-1">
                <div>
                  <span className="text-muted-foreground">{t("time")}: </span>
                  {formatTime(selectedEntry.timestamp)}
                </div>
                <div>
                  <span className="text-muted-foreground">Method: </span>
                  <span className="font-mono text-primary">
                    {selectedEntry.event.method}
                  </span>
                </div>
                <div>
                  <span className="text-muted-foreground">Call Type: </span>
                  {selectedEntry.event.callType}
                </div>
                <div>
                  <span className="text-muted-foreground">Thread ID: </span>
                  {selectedEntry.event.threadId}
                </div>
                {selectedEntry.event.library && (
                  <div>
                    <span className="text-muted-foreground">Library: </span>
                    {selectedEntry.event.library}
                  </div>
                )}
              </div>

              {selectedEntry.event.args.length > 0 && (
                <div>
                  <div className="text-muted-foreground mb-1">Arguments</div>
                  <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                    {selectedEntry.event.args
                      .map((a, i) => `[${i}] ${a}`)
                      .join("\n")}
                  </pre>
                </div>
              )}

              {selectedEntry.event.ret && (
                <div>
                  <div className="text-muted-foreground mb-1">Return Value</div>
                  <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-20 whitespace-pre-wrap break-all">
                    {selectedEntry.event.ret}
                  </pre>
                </div>
              )}

              {selectedEntry.event.backtrace &&
                selectedEntry.event.backtrace.length > 0 && (
                  <div>
                    <div className="text-muted-foreground mb-1">Backtrace</div>
                    <div className="rounded border bg-muted/20 p-2 overflow-auto max-h-60 text-[10px] font-mono space-y-0.5">
                      {selectedEntry.event.backtrace.map((frame, i) => (
                        <div
                          key={i}
                          className="p-1 rounded hover:bg-muted/50 break-all"
                        >
                          <span className="text-muted-foreground mr-2">
                            #{i}
                          </span>
                          {frame}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
            </div>
          )}
        </div>
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
