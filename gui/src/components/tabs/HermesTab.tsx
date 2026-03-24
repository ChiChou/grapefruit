import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { Download, Trash2, RefreshCw, FileSearch } from "lucide-react";

import { useDock } from "@/context/DockContext";

import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Status, useSession } from "@/context/SessionContext";

interface HermesEntry {
  id: number;
  url: string;
  hash: string;
  size: number;
  createdAt: string | null;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function filenameFromUrl(url: string): string {
  const parts = url.split("/");
  return parts[parts.length - 1] || url;
}

function filenameFromUrlShort(url: string): string {
  const name = filenameFromUrl(url);
  return name.length > 30 ? name.slice(0, 27) + "..." : name;
}

export function HermesTab() {
  const { socket, status, device, identifier } = useSession();
  const { openFilePanel } = useDock();
  const [entries, setEntries] = useState<HermesEntry[]>([]);
  const [sortBy, setSortBy] = useState<"id" | "hash">("id");

  // Load historical data
  const { data: history, refetch: refetchHistory } = useQuery<{
    logs: HermesEntry[];
    total: number;
  }>({
    queryKey: ["hermesHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(`/api/hermes/${device}/${identifier}?limit=1000`);
      if (!res.ok) throw new Error("Failed to load Hermes history");
      return res.json();
    },
    enabled: !!device && !!identifier,
    staleTime: Infinity,
    gcTime: 0,
  });

  // Merge history into entries on load
  useEffect(() => {
    if (history?.logs) {
      setEntries(history.logs);
    }
  }, [history]);

  // Live socket events with batching
  const pendingRef = useRef<HermesEntry[]>([]);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const nextIdRef = useRef(100000);

  const flushPending = useCallback(() => {
    timerRef.current = null;
    if (pendingRef.current.length === 0) return;

    const newEntries = pendingRef.current;
    pendingRef.current = [];

    setEntries((prev) => [...newEntries, ...prev]);
  }, []);

  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    const onHermes = (event: { url: string; hash: string; size: number }) => {
      const entry: HermesEntry = {
        id: nextIdRef.current++,
        url: event.url,
        hash: event.hash,
        size: event.size,
        createdAt: new Date().toISOString(),
      };
      pendingRef.current.push(entry);
      if (!timerRef.current) {
        timerRef.current = setTimeout(flushPending, 100);
      }
    };

    socket.on("hermes", onHermes);
    return () => {
      socket.off("hermes", onHermes);
      if (timerRef.current) {
        clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, [socket, status, flushPending]);

  // Delete mutation
  const clearMutation = useMutation({
    mutationFn: async () => {
      if (!device || !identifier) return;
      const res = await fetch(`/api/hermes/${device}/${identifier}`, {
        method: "DELETE",
      });
      if (!res.ok) throw new Error("Failed to clear Hermes records");
    },
    onSuccess: () => {
      setEntries([]);
      refetchHistory();
    },
  });

  // Download handler
  const handleDownload = async (entry: HermesEntry) => {
    try {
      const res = await fetch(
        `/api/hermes/${device}/${identifier}/download/${entry.id}`,
      );
      if (!res.ok) throw new Error("Download failed");

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filenameFromUrl(entry.url);
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Failed to download Hermes:", error);
    }
  };

  // Sorted entries
  const sortedEntries = useMemo(() => {
    const sorted = [...entries];
    if (sortBy === "hash") {
      sorted.sort((a, b) => a.hash.localeCompare(b.hash));
    }
    // Default (id) is already desc from server + prepend
    return sorted;
  }, [entries, sortBy]);

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b">
        <h2 className="text-sm font-semibold">Hermes Capture</h2>
        <Badge variant="secondary" className="text-xs">
          {entries.length}
        </Badge>
        <div className="flex-1" />
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setSortBy(sortBy === "id" ? "hash" : "id")}
        >
          Sort: {sortBy === "id" ? "Newest" : "Hash"}
        </Button>
        <Button size="sm" variant="ghost" onClick={() => refetchHistory()}>
          <RefreshCw className="w-3.5 h-3.5" />
        </Button>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => clearMutation.mutate()}
          disabled={clearMutation.isPending || entries.length === 0}
        >
          <Trash2 className="w-3.5 h-3.5" />
        </Button>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">ID</TableHead>
              <TableHead>File</TableHead>
              <TableHead className="w-40">Hash</TableHead>
              <TableHead className="w-20 text-right">Size</TableHead>
              <TableHead className="w-44">Time</TableHead>
              <TableHead className="w-12" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {sortedEntries.map((entry) => (
              <TableRow key={`${entry.id}-${entry.hash}`}>
                <TableCell className="text-xs text-muted-foreground">
                  {entry.id}
                </TableCell>
                <TableCell
                  className="font-mono text-xs truncate max-w-[300px]"
                  title={entry.url}
                >
                  {filenameFromUrl(entry.url)}
                </TableCell>
                <TableCell
                  className="font-mono text-xs text-muted-foreground"
                  title={entry.hash}
                >
                  {entry.hash.slice(0, 16)}...
                </TableCell>
                <TableCell className="text-xs text-right">
                  {formatSize(entry.size)}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {entry.createdAt
                    ? new Date(entry.createdAt).toLocaleTimeString()
                    : "-"}
                </TableCell>
                <TableCell className="flex gap-0.5">
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 w-6 p-0"
                    onClick={() =>
                      openFilePanel({
                        id: `hermes_analysis_${entry.id}`,
                        component: "hermesAnalysis",
                        title: `HBC: ${filenameFromUrlShort(entry.url)}`,
                        params: {
                          entryId: entry.id,
                          filename: filenameFromUrl(entry.url),
                        },
                      })
                    }
                    title="Analyze"
                  >
                    <FileSearch className="w-3.5 h-3.5" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 w-6 p-0"
                    onClick={() => handleDownload(entry)}
                    title="Download"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </Button>
                </TableCell>
              </TableRow>
            ))}
            {sortedEntries.length === 0 && (
              <TableRow>
                <TableCell
                  colSpan={6}
                  className="text-center text-muted-foreground text-sm py-8"
                >
                  No Hermes captures yet. Start RN hooks to intercept Hermes
                  bytecode.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
