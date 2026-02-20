import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  useReactTable,
  getCoreRowModel,
  flexRender,
  type ColumnDef,
} from "@tanstack/react-table";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useQuery, useMutation } from "@tanstack/react-query";

import {
  Trash2,
  Play,
  Square,
  Loader2,
  ArrowDown,
  ArrowUp,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import XPCTreeView from "@/components/shared/XPCTreeView";
import { Status, useSession } from "@/context/SessionContext";

import {
  isNSXPCMessage,
  type XPCSocketEvent,
  type XPCNode,
  type NSXPCMessage,
} from "@/lib/rpc";

interface XPCEntry {
  id: number;
  timestamp: Date;
  dir: "<" | ">";
  name: string;
  peer: number;
  message: XPCNode;
  backtrace?: string[];
}

interface NSXPCEntry {
  id: number;
  timestamp: Date;
  dir: "<" | ">";
  name: string;
  peer: number;
  sel: string;
  args: string[];
  description: string;
  backtrace?: string[];
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

function messagePreview(message: XPCNode): string {
  const desc = message.description;
  if (typeof desc === "string") {
    return desc.length > 120 ? `${desc.slice(0, 120)}...` : desc;
  }
  return JSON.stringify(message).slice(0, 120);
}

function argsPreview(args: string[]): string {
  if (!args || args.length === 0) return "";
  const joined = args.join(", ");
  return joined.length > 80 ? `${joined.slice(0, 80)}...` : joined;
}

const DirCell = ({ dir }: { dir: "<" | ">" }) =>
  dir === "<" ? (
    <ArrowDown className="w-3.5 h-3.5 text-green-500" />
  ) : (
    <ArrowUp className="w-3.5 h-3.5 text-blue-500" />
  );

// XPC table columns
const xpcColumns: ColumnDef<XPCEntry>[] = [
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
    id: "dir",
    header: "",
    size: 32,
    cell: ({ row }) => <DirCell dir={row.original.dir} />,
  },
  {
    id: "service",
    header: "Service",
    size: 180,
    cell: ({ row }) => (
      <span className="font-mono text-primary truncate" title={row.original.name}>
        {row.original.name || "-"}
      </span>
    ),
  },
  {
    id: "pid",
    header: "PID",
    size: 56,
    cell: ({ row }) => (
      <span className="font-mono text-muted-foreground">
        {row.original.peer || "-"}
      </span>
    ),
  },
  {
    id: "message",
    header: "Message",
    size: 300,
    cell: ({ row }) => (
      <span
        className="font-mono text-muted-foreground truncate"
        title={messagePreview(row.original.message)}
      >
        {messagePreview(row.original.message)}
      </span>
    ),
  },
];

// NSXPC table columns
const nsxpcColumns: ColumnDef<NSXPCEntry>[] = [
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
    id: "dir",
    header: "",
    size: 32,
    cell: ({ row }) => <DirCell dir={row.original.dir} />,
  },
  {
    id: "service",
    header: "Service",
    size: 150,
    cell: ({ row }) => (
      <span className="font-mono text-primary truncate" title={row.original.name}>
        {row.original.name || "-"}
      </span>
    ),
  },
  {
    id: "pid",
    header: "PID",
    size: 56,
    cell: ({ row }) => (
      <span className="font-mono text-muted-foreground">
        {row.original.peer || "-"}
      </span>
    ),
  },
  {
    id: "selector",
    header: "Selector",
    size: 200,
    cell: ({ row }) => (
      <span className="font-mono text-primary truncate" title={row.original.sel}>
        {row.original.sel}
      </span>
    ),
  },
  {
    id: "args",
    header: "Args",
    size: 200,
    cell: ({ row }) => {
      const text = argsPreview(row.original.args);
      return (
        <span className="font-mono text-muted-foreground truncate" title={text}>
          {text || "--"}
        </span>
      );
    },
  },
];

function VirtualTable<T extends { id: number }>({
  table,
  columns,
  selectedId,
  onSelect,
}: {
  table: ReturnType<typeof useReactTable<T>>;
  columns: ColumnDef<T>[];
  selectedId: number | null;
  onSelect: (id: number | null) => void;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { rows } = table.getRowModel();

  const rowVirtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => containerRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();
  const totalSize = rowVirtualizer.getTotalSize();

  return (
    <div ref={containerRef} className="flex-1 overflow-auto">
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
                  {flexRender(
                    header.column.columnDef.header,
                    header.getContext(),
                  )}
                </th>
              ))}
            </tr>
          ))}
        </thead>
        <tbody>
          {virtualRows.length > 0 && virtualRows[0].start > 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{ height: virtualRows[0].start }}
              />
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
                  onSelect(
                    selectedId === row.original.id ? null : row.original.id,
                  )
                }
              >
                {row.getVisibleCells().map((cell) => (
                  <td
                    key={cell.id}
                    className="p-2 truncate"
                    style={{
                      width: cell.column.getSize(),
                      maxWidth: cell.column.getSize(),
                    }}
                  >
                    {flexRender(
                      cell.column.columnDef.cell,
                      cell.getContext(),
                    )}
                  </td>
                ))}
              </tr>
            );
          })}
          {virtualRows.length > 0 && (
            <tr>
              <td
                colSpan={columns.length}
                style={{
                  height:
                    totalSize -
                    (virtualRows[virtualRows.length - 1]?.end ?? 0),
                }}
              />
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function XPCDetailPanel({ entry }: { entry: XPCEntry | null }) {
  if (!entry) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground text-xs">
        Select a message to view details
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-3 text-xs space-y-3">
      <div>
        <div className="text-muted-foreground mb-1">Message</div>
        <div className="rounded border bg-muted/20 p-2 overflow-auto max-h-[60vh]">
          <XPCTreeView node={entry.message} />
        </div>
      </div>

      {entry.backtrace && entry.backtrace.length > 0 && (
        <div>
          <div className="text-muted-foreground mb-1">Backtrace</div>
          <div className="rounded border bg-muted/20 p-2 overflow-auto max-h-60 text-[10px] font-mono space-y-0.5">
            {entry.backtrace.map((frame, i) => (
              <div key={i} className="p-1 rounded hover:bg-muted/50 break-all">
                <span className="text-muted-foreground mr-2">#{i}</span>
                {frame}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function NSXPCDetailPanel({ entry }: { entry: NSXPCEntry | null }) {
  if (!entry) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground text-xs">
        Select a message to view details
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto p-3 text-xs space-y-3">
      <div className="space-y-1">
        <div>
          <span className="text-muted-foreground">Selector: </span>
          <span className="font-mono text-primary">{entry.sel}</span>
        </div>
      </div>

      <div>
        <div className="text-muted-foreground mb-1">Description</div>
        <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-20 whitespace-pre-wrap break-all">
          {entry.description}
        </pre>
      </div>

      {entry.args.length > 0 && (
        <div>
          <div className="text-muted-foreground mb-1">Arguments</div>
          <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
            {entry.args.map((a, i) => `[${i}] ${a}`).join("\n")}
          </pre>
        </div>
      )}

      {entry.backtrace && entry.backtrace.length > 0 && (
        <div>
          <div className="text-muted-foreground mb-1">Backtrace</div>
          <div className="rounded border bg-muted/20 p-2 overflow-auto max-h-60 text-[10px] font-mono space-y-0.5">
            {entry.backtrace.map((frame, i) => (
              <div key={i} className="p-1 rounded hover:bg-muted/50 break-all">
                <span className="text-muted-foreground mr-2">#{i}</span>
                {frame}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

interface XPCHistoryLog {
  id: number;
  timestamp: string;
  protocol: string;
  event: string;
  direction: string;
  service: string | null;
  peer: number | null;
  message?: XPCNode | NSXPCMessage;
  backtrace?: string[];
  createdAt: string;
}

export function FruityXPCTab() {
  const { socket, status, device, identifier, fruity } = useSession();

  const [xpcEntries, setXpcEntries] = useState<XPCEntry[]>([]);
  const [nsxpcEntries, setNsxpcEntries] = useState<NSXPCEntry[]>([]);
  const [selectedXpcId, setSelectedXpcId] = useState<number | null>(null);
  const [selectedNsxpcId, setSelectedNsxpcId] = useState<number | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [hookEnabled, setHookEnabled] = useState(false);
  const [hookLoading, setHookLoading] = useState(false);

  const xpcIdRef = useRef(1);
  const nsxpcIdRef = useRef(1);
  const pendingXpcRef = useRef<XPCEntry[]>([]);
  const pendingNsxpcRef = useRef<NSXPCEntry[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const handleToggleHook = async (enabled: boolean) => {
    if (!fruity) return;
    setHookLoading(true);
    try {
      if (enabled) {
        await fruity.taps.start("xpc");
      } else {
        await fruity.taps.stop("xpc");
      }
      setHookEnabled(enabled);
    } catch (error) {
      console.error(
        `Failed to ${enabled ? "start" : "stop"} XPC hook:`,
        error,
      );
    } finally {
      setHookLoading(false);
    }
  };

  // Load persisted history
  const { data: history } = useQuery<{ logs: XPCHistoryLog[] }>({
    queryKey: ["xpcHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(
        `/api/history/xpc/${device}/${identifier}?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load XPC history");
      return res.json();
    },
    enabled: status === Status.Ready && !!device && !!identifier,
    staleTime: Infinity,
  });

  useEffect(() => {
    if (!history?.logs) return;

    const xpc: XPCEntry[] = [];
    const nsxpc: NSXPCEntry[] = [];

    for (const record of [...history.logs].reverse()) {
      if (!record.message) continue;
      const msg = record.message;

      if (isNSXPCMessage(msg)) {
        nsxpc.push({
          id: nsxpcIdRef.current++,
          timestamp: new Date(record.timestamp),
          dir: record.direction as "<" | ">",
          name: record.service ?? "",
          peer: record.peer ?? 0,
          sel: msg.sel,
          args: msg.args,
          description: msg.description,
          backtrace: record.backtrace,
        });
      } else {
        xpc.push({
          id: xpcIdRef.current++,
          timestamp: new Date(record.timestamp),
          dir: record.direction as "<" | ">",
          name: record.service ?? "",
          peer: record.peer ?? 0,
          message: msg,
          backtrace: record.backtrace,
        });
      }
    }

    setXpcEntries(xpc);
    setNsxpcEntries(nsxpc);
  }, [history]);

  // Clear mutation
  const clearMutation = useMutation({
    mutationFn: async () => {
      if (!device || !identifier) return;
      const res = await fetch(`/api/history/xpc/${device}/${identifier}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to clear XPC history");
    },
    onSuccess: () => {
      setXpcEntries([]);
      setNsxpcEntries([]);
      setSelectedXpcId(null);
      setSelectedNsxpcId(null);
      xpcIdRef.current = 1;
      nsxpcIdRef.current = 1;
      pendingXpcRef.current = [];
      pendingNsxpcRef.current = [];
    },
  });

  const flushPending = useCallback(() => {
    timerRef.current = null;

    if (pendingXpcRef.current.length > 0) {
      const incoming = pendingXpcRef.current;
      pendingXpcRef.current = [];
      setXpcEntries((prev) => {
        const merged = [...prev, ...incoming];
        return merged.length > MAX_ENTRIES ? merged.slice(-MAX_ENTRIES) : merged;
      });
    }

    if (pendingNsxpcRef.current.length > 0) {
      const incoming = pendingNsxpcRef.current;
      pendingNsxpcRef.current = [];
      setNsxpcEntries((prev) => {
        const merged = [...prev, ...incoming];
        return merged.length > MAX_ENTRIES ? merged.slice(-MAX_ENTRIES) : merged;
      });
    }
  }, []);

  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onXpc = (raw: XPCSocketEvent) => {
      const msg = raw.message;

      if (isNSXPCMessage(msg)) {
        pendingNsxpcRef.current.push({
          id: nsxpcIdRef.current++,
          timestamp: new Date(),
          dir: raw.dir,
          name: raw.name ?? "",
          peer: raw.peer ?? 0,
          sel: msg.sel,
          args: msg.args,
          description: msg.description,
          backtrace: raw.backtrace,
        });
      } else {
        pendingXpcRef.current.push({
          id: xpcIdRef.current++,
          timestamp: new Date(),
          dir: raw.dir,
          name: raw.name ?? "",
          peer: raw.peer ?? 0,
          message: msg,
          backtrace: raw.backtrace,
        });
      }

      if (!timerRef.current) {
        timerRef.current = setTimeout(flushPending, THROTTLE_MS);
      }
    };

    socket.on("xpc", onXpc);
    return () => {
      socket.off("xpc", onXpc);
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [status, socket, flushPending]);

  const handleClear = () => {
    setXpcEntries([]);
    setNsxpcEntries([]);
    setSelectedXpcId(null);
    setSelectedNsxpcId(null);
    xpcIdRef.current = 1;
    nsxpcIdRef.current = 1;
    pendingXpcRef.current = [];
    pendingNsxpcRef.current = [];
    clearMutation.mutate();
  };

  // Filtered entries
  const filteredXpc = useMemo(() => {
    const q = searchFilter.trim().toLowerCase();
    if (!q) return xpcEntries;
    return xpcEntries.filter(
      (e) =>
        (e.name?.toLowerCase().includes(q) ?? false) ||
        messagePreview(e.message).toLowerCase().includes(q),
    );
  }, [xpcEntries, searchFilter]);

  const filteredNsxpc = useMemo(() => {
    const q = searchFilter.trim().toLowerCase();
    if (!q) return nsxpcEntries;
    return nsxpcEntries.filter(
      (e) =>
        e.sel.toLowerCase().includes(q) ||
        e.description.toLowerCase().includes(q) ||
        (e.name?.toLowerCase().includes(q) ?? false),
    );
  }, [nsxpcEntries, searchFilter]);

  const selectedXpc = useMemo(
    () => filteredXpc.find((e) => e.id === selectedXpcId) ?? null,
    [filteredXpc, selectedXpcId],
  );

  const selectedNsxpc = useMemo(
    () => filteredNsxpc.find((e) => e.id === selectedNsxpcId) ?? null,
    [filteredNsxpc, selectedNsxpcId],
  );

  const xpcTable = useReactTable({
    data: filteredXpc,
    columns: xpcColumns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => String(row.id),
  });

  const nsxpcTable = useReactTable({
    data: filteredNsxpc,
    columns: nsxpcColumns,
    getCoreRowModel: getCoreRowModel(),
    getRowId: (row) => String(row.id),
  });

  const notReady = status !== Status.Ready;

  return (
    <div className="flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 p-2 border-b shrink-0">
        {hookEnabled ? (
          <Button
            variant="outline"
            size="sm"
            className="h-8 px-2.5 text-xs text-red-500 hover:text-red-600"
            onClick={() => handleToggleHook(false)}
            disabled={hookLoading || notReady}
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
            disabled={hookLoading || notReady}
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
          value={searchFilter}
          onChange={(e) => setSearchFilter(e.target.value)}
          placeholder="Filter..."
          className="h-8 max-w-xs"
        />
        <span className="text-xs text-muted-foreground ml-auto">
          {xpcEntries.length + nsxpcEntries.length} event
          {xpcEntries.length + nsxpcEntries.length !== 1 ? "s" : ""}
        </span>
        <Button
          variant="ghost"
          size="icon"
          className="h-8 w-8 text-red-500 hover:text-red-600 hover:bg-red-100 dark:hover:bg-red-950/30"
          onClick={handleClear}
          disabled={xpcEntries.length === 0 && nsxpcEntries.length === 0}
        >
          <Trash2 className="h-4 w-4" />
        </Button>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="xpc" className="flex-1 flex flex-col min-h-0">
        <TabsList variant="line" className="mx-2 mt-1">
          <TabsTrigger value="xpc">XPC ({filteredXpc.length})</TabsTrigger>
          <TabsTrigger value="nsxpc">NSXPC ({filteredNsxpc.length})</TabsTrigger>
        </TabsList>

        <TabsContent value="xpc" className="flex-1 min-h-0">
          <ResizablePanelGroup
            orientation="horizontal"
            className="h-full"
            autoSaveId="xpc-split"
          >
            <ResizablePanel defaultSize="65%" minSize="30%">
              <div className="h-full flex flex-col overflow-hidden">
                <VirtualTable
                  table={xpcTable}
                  columns={xpcColumns}
                  selectedId={selectedXpcId}
                  onSelect={setSelectedXpcId}
                />
              </div>
            </ResizablePanel>
            <ResizableHandle />
            <ResizablePanel defaultSize="35%" minSize="15%">
              <XPCDetailPanel entry={selectedXpc} />
            </ResizablePanel>
          </ResizablePanelGroup>
        </TabsContent>

        <TabsContent value="nsxpc" className="flex-1 min-h-0">
          <ResizablePanelGroup
            orientation="horizontal"
            className="h-full"
            autoSaveId="nsxpc-split"
          >
            <ResizablePanel defaultSize="65%" minSize="30%">
              <div className="h-full flex flex-col overflow-hidden">
                <VirtualTable
                  table={nsxpcTable}
                  columns={nsxpcColumns}
                  selectedId={selectedNsxpcId}
                  onSelect={setSelectedNsxpcId}
                />
              </div>
            </ResizablePanel>
            <ResizableHandle />
            <ResizablePanel defaultSize="35%" minSize="15%">
              <NSXPCDetailPanel entry={selectedNsxpc} />
            </ResizablePanel>
          </ResizablePanelGroup>
        </TabsContent>
      </Tabs>
    </div>
  );
}
