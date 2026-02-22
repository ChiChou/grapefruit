import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { useTranslation } from "react-i18next";
import { type ColumnDef } from "@tanstack/react-table";

import { Trash2, Play, Square, Loader2, ChevronsDown } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { LogTable } from "@/components/shared/LogTable";
import { Status, useSession } from "@/context/SessionContext";
import { useLogStream } from "@/hooks/useLogStream";
import { toTime } from "@/lib/format";

const TAP_ID = "jni";
import type { JNIEvent } from "@agent/droid/hooks/jni";

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

function argsPreview(args: string[]): string {
  if (!args || args.length === 0) return "";
  const joined = args.join(", ");
  return joined.length > 80 ? `${joined.slice(0, 80)}...` : joined;
}

const mapHistory = (record: Record<string, unknown>, id: number): JNIEntry => ({
  id,
  timestamp: new Date(record.timestamp as string),
  event: {
    type: (record.type as string) ?? "trace",
    method: record.method as string,
    callType: (record.callType as string) ?? "JNIEnv",
    threadId: (record.threadId as number) ?? 0,
    args: (record.args as string[]) ?? [],
    ret: (record.ret as string) ?? "",
    backtrace: record.backtrace as string[] | undefined,
    library: record.library as string | null | undefined,
  },
});

const mapSocket = (id: number, ...args: unknown[]): JNIEntry => {
  const raw = args[0] as JNIEvent;
  return {
    id,
    timestamp: new Date(),
    event: {
      type: raw.type,
      method: raw.method,
      callType: raw.callType,
      threadId: raw.threadId,
      args: raw.args,
      ret: raw.ret,
      library: raw.type === "load" ? raw.library : undefined,
    },
  };
};

const columns: ColumnDef<JNIEntry>[] = [
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
      <span
        className="font-mono text-primary truncate"
        title={row.original.event.method}
      >
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
  const { status, device, identifier, droid } = useSession();

  const [isActive, setIsActive] = useState<boolean | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const {
    entries,
    selectedId,
    setSelectedId,
    clear,
    clearMutation,
  } = useLogStream<JNIEntry>({
    event: "jni",
    path: "history/jni",
    key: "logs",
    fromRecord: mapHistory,
    fromEvent: mapSocket,
  });

  // Sync initial active state from agent
  const { data: initialActive } = useQuery({
    queryKey: ["jniActive", device],
    queryFn: () => droid!.taps.active(TAP_ID),
    enabled: status === Status.Ready && !!droid,
  });

  useEffect(() => {
    if (initialActive !== undefined && isActive === null)
      setIsActive(initialActive);
  }, [initialActive, isActive]);

  // Reset active state on session change
  useEffect(() => {
    setIsActive(false);
  }, [device, identifier]);

  // Toggle start/stop
  const toggleMutation = useMutation({
    mutationFn: async (enable: boolean) => {
      if (!droid) return;
      if (enable) {
        await droid.taps.start(TAP_ID);
      } else {
        await droid.taps.stop(TAP_ID);
      }
    },
    onSuccess: (_, enable) => {
      setIsActive(enable);
    },
  });

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
                disabled={notReady || toggleMutation.isPending || !droid}
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
              placeholder="Filter..."
              className="h-8 max-w-xs"
            />
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
              <Trash2 className="h-4 w-4" />
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
              Select an event to view details
            </div>
          ) : (
            <div className="space-y-3">
              <div className="space-y-1">
                <div>
                  <span className="text-muted-foreground">{t("time")}: </span>
                  {toTime(selectedEntry.timestamp)}
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
