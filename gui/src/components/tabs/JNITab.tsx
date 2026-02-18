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

import { ChevronsDown, Trash2 } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { Switch } from "@/components/ui/switch";
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

interface JNIRowProps {
  entries: JNIEntry[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

function JNIRow(
  props: {
    ariaAttributes: {
      "aria-posinset": number;
      "aria-setsize": number;
      role: "listitem";
    };
    index: number;
    style: CSSProperties;
  } & JNIRowProps,
) {
  const { index, style, entries, selectedId, onSelect } = props;
  const entry = entries[index];
  if (!entry) return null;

  const { event } = entry;
  const isLoad = event.type === "load";

  return (
    <button
      type="button"
      style={style}
      onClick={() => onSelect(entry.id)}
      className={`w-full flex items-center gap-2 px-2 border-b text-left text-sm hover:bg-muted/40 ${
        selectedId === entry.id ? "bg-muted" : ""
      }`}
    >
      <span className="font-mono text-muted-foreground w-24 shrink-0">
        {formatTime(entry.timestamp)}
      </span>
      <span className="font-mono text-muted-foreground w-12 shrink-0 text-center">
        {event.threadId ?? "-"}
      </span>
      <Badge
        variant={
          isLoad
            ? "outline"
            : event.callType === "JavaVM"
              ? "secondary"
              : "default"
        }
        className="h-5 px-1.5 text-[10px] shrink-0 w-14 justify-center"
      >
        {isLoad ? "load" : event.callType}
      </Badge>
      <span
        className="font-mono text-primary truncate w-52 shrink-0"
        title={event.method}
      >
        {event.method}
      </span>
      <span
        className="font-mono text-muted-foreground truncate min-w-0"
        title={argsPreview(event.args)}
      >
        {argsPreview(event.args) || "--"}
      </span>
    </button>
  );
}

export function JNITab() {
  const { t } = useTranslation();
  const { status, socket, device, identifier, droid } = useSession();

  const [isActive, setIsActive] = useState(false);
  const [entries, setEntries] = useState<JNIEntry[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [searchFilter, setSearchFilter] = useState("");

  const idRef = useRef(1);
  const listRef = useRef<ListImperativeAPI>(null);
  const pendingRef = useRef<JNIEntry[]>([]);
  const rafRef = useRef<number | null>(null);
  const lastFlushRef = useRef(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [listHeight, setListHeight] = useState(320);

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
    gcTime: 0,
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
      if (!rafRef.current) {
        rafRef.current = requestAnimationFrame(() => {
          rafRef.current = null;
          flushPending();
        });
      }
    };

    socket.on("jni", onJNI);
    return () => {
      socket.off("jni", onJNI);
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

  const scrollToLatest = useCallback(() => {
    if (filteredEntries.length === 0) return;
    listRef.current?.scrollToRow({
      index: filteredEntries.length - 1,
      align: "end",
    });
  }, [filteredEntries.length]);

  if (status !== Status.Ready) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("flutter_waiting")}
      </div>
    );
  }

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="jni-split"
    >
      {/* Left: toolbar + event list */}
      <ResizablePanel defaultSize="65%" minSize="30%">
        <div className="h-full flex flex-col gap-2 p-3 overflow-hidden">
          {/* Toolbar */}
          <div className="flex items-center gap-2 shrink-0">
            <label className="flex items-center gap-2 text-sm shrink-0">
              <Switch
                checked={isActive}
                onCheckedChange={(checked) => toggleMutation.mutate(checked)}
                disabled={toggleMutation.isPending || !droid}
              />
              JNI Trace
            </label>
            <Input
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter..."
              className="max-w-xs"
            />
            <span className="text-xs text-muted-foreground ml-auto shrink-0">
              {filteredEntries.length} events
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0"
              onClick={scrollToLatest}
              disabled={filteredEntries.length === 0}
              title="Scroll to latest"
            >
              <ChevronsDown className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7 shrink-0 text-destructive hover:text-destructive hover:bg-destructive/10"
              onClick={() => clearMutation.mutate()}
              disabled={clearMutation.isPending || entries.length === 0}
              title="Clear history"
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>

          {/* Event table */}
          <div className="flex-1 min-h-0 border rounded-md overflow-hidden flex flex-col">
            <div className="grid grid-cols-[96px_48px_56px_208px_minmax(0,1fr)] gap-2 px-2 py-1 border-b bg-muted/40 text-[10px] uppercase tracking-wide text-muted-foreground shrink-0">
              <span>{t("hook_timestamp")}</span>
              <span>TID</span>
              <span>Type</span>
              <span>{t("method")}</span>
              <span>{t("args")}</span>
            </div>

            <div ref={containerRef} className="flex-1 min-h-0">
              {filteredEntries.length === 0 ? (
                <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
                  {isActive
                    ? "Waiting for JNI calls..."
                    : "Toggle the switch to start tracing JNI calls"}
                </div>
              ) : (
                <List
                  listRef={listRef}
                  style={{ height: listHeight, width: "100%" }}
                  rowCount={filteredEntries.length}
                  rowHeight={ROW_HEIGHT}
                  rowComponent={JNIRow}
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
