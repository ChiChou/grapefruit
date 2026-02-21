import { useCallback, useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Play, Square, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import HexView from "@/components/shared/HexView";
import { Platform, Status, useSession } from "@/context/SessionContext";
import { usePlatformRpcQuery } from "@/lib/queries";
import type { MemoryScanEvent } from "@/lib/rpc";

type DataType =
  | "hex"
  | "utf8"
  | "utf16"
  | "int8"
  | "uint8"
  | "int16"
  | "uint16"
  | "int32"
  | "uint32"
  | "float"
  | "double";

interface ScanResult {
  address: string;
  size: number;
  preview: Uint8Array;
}

const ROW_HEIGHT = 28;
const MAX_RESULTS = 10000;

function toHexPattern(dataType: DataType, input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  switch (dataType) {
    case "hex":
      return trimmed;

    case "utf8":
      return Array.from(new TextEncoder().encode(trimmed))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");

    case "utf16": {
      const bytes: string[] = [];
      for (let i = 0; i < trimmed.length; i++) {
        const code = trimmed.charCodeAt(i);
        bytes.push((code & 0xff).toString(16).padStart(2, "0"));
        bytes.push(((code >> 8) & 0xff).toString(16).padStart(2, "0"));
      }
      return bytes.join(" ");
    }

    case "int8":
    case "uint8": {
      const n = parseInt(trimmed, 10);
      if (isNaN(n)) return null;
      const v = dataType === "int8" ? (n < 0 ? (n + 256) & 0xff : n & 0xff) : n & 0xff;
      return v.toString(16).padStart(2, "0");
    }

    case "int16":
    case "uint16": {
      const n = parseInt(trimmed, 10);
      if (isNaN(n)) return null;
      const v = dataType === "int16" ? (n < 0 ? (n + 65536) & 0xffff : n & 0xffff) : n & 0xffff;
      return [v & 0xff, (v >> 8) & 0xff]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
    }

    case "int32":
    case "uint32": {
      const n = parseInt(trimmed, 10);
      if (isNaN(n)) return null;
      const v = n >>> 0;
      return [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff]
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
    }

    case "float": {
      const n = parseFloat(trimmed);
      if (isNaN(n)) return null;
      const buf = new ArrayBuffer(4);
      new DataView(buf).setFloat32(0, n, true);
      return Array.from(new Uint8Array(buf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
    }

    case "double": {
      const n = parseFloat(trimmed);
      if (isNaN(n)) return null;
      const buf = new ArrayBuffer(8);
      new DataView(buf).setFloat64(0, n, true);
      return Array.from(new Uint8Array(buf))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(" ");
    }
  }
}

function formatHexPreview(data: Uint8Array): string {
  const hex = Array.from(data.slice(0, 16))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");
  const ascii = Array.from(data.slice(0, 16))
    .map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."))
    .join("");
  return `${hex}  ${ascii}`;
}

const DUMP_SIZE = 256;

interface AddressInfo {
  module: { name: string; base: string; size: number; path: string } | null;
  range: { base: string; size: number; protection: string; file: { path: string; offset: number; size: number } | null } | null;
}

function DetailPanel({ address }: { address: string }) {
  const { data, isLoading, error } = usePlatformRpcQuery<ArrayBuffer | null>(
    ["memoryScanDetail", address],
    (api) => api.memory.dump(address, DUMP_SIZE),
  );

  const { data: info } = usePlatformRpcQuery<AddressInfo>(
    ["memoryScanInfo", address],
    (api) => api.memory.addressInfo(address),
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-xs">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-red-500 text-xs">
        {(error as Error).message}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-xs">
        No data
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="px-3 py-1.5 border-b shrink-0 space-y-0.5">
        <div className="text-xs font-mono">{address}</div>
        {info?.module && (
          <div className="text-xs text-muted-foreground">
            <span className="text-primary">{info.module.name}</span>
            {" + "}
            <span className="font-mono">
              0x{(parseInt(address, 16) - parseInt(info.module.base, 16)).toString(16)}
            </span>
            <span className="ml-2 truncate" title={info.module.path}>
              {info.module.path}
            </span>
          </div>
        )}
        {info?.range && (
          <div className="text-xs text-muted-foreground">
            <span className="font-mono">{info.range.protection}</span>
            <span className="ml-2">
              {info.range.base} ({info.range.size} bytes)
            </span>
            {info.range.file && (
              <span className="ml-2 truncate" title={info.range.file.path}>
                {info.range.file.path}
              </span>
            )}
          </div>
        )}
      </div>
      <div className="flex-1 overflow-auto p-2">
        <HexView data={new Uint8Array(data)} stride={16} />
      </div>
    </div>
  );
}

export function MemoryScanTab() {
  const { platform, status, socket, fruity, droid } = useSession();

  const api = platform === Platform.Fruity ? fruity : droid;

  const [dataType, setDataType] = useState<DataType>("hex");
  const [pattern, setPattern] = useState("");
  const [protR, setProtR] = useState(true);
  const [protW, setProtW] = useState(false);
  const [protX, setProtX] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [progress, setProgress] = useState<{ current: number; total: number }>({ current: 0, total: 0 });
  const [matchCount, setMatchCount] = useState(0);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);

  const listRef = useRef<HTMLDivElement>(null);

  const scanMutation = useMutation({
    mutationFn: async () => {
      const hexPattern = toHexPattern(dataType, pattern);
      if (!hexPattern || !api) throw new Error("Invalid pattern");
      setResults([]);
      setMatchCount(0);
      setProgress({ current: 0, total: 0 });
      setSelectedAddress(null);
      setScanning(true);
      const prot = `${protR ? "r" : "-"}${protW ? "w" : "-"}${protX ? "x" : "-"}`;
      await api.memory.scan(hexPattern, prot);
    },
    onError: () => {
      setScanning(false);
    },
  });

  const stopMutation = useMutation({
    mutationFn: async () => {
      if (!api) return;
      await api.memory.stopScan();
    },
    onSuccess: () => {
      setScanning(false);
    },
  });

  const handleEvent = useCallback((event: MemoryScanEvent, data?: ArrayBuffer) => {
    switch (event.event) {
      case "match":
        setMatchCount((c) => c + 1);
        setResults((prev) => {
          if (prev.length >= MAX_RESULTS) return prev;
          return [
            ...prev,
            {
              address: event.address!,
              size: event.size!,
              preview: data ? new Uint8Array(data) : new Uint8Array(),
            },
          ];
        });
        break;
      case "progress":
        setProgress({ current: event.current!, total: event.total! });
        break;
      case "done":
        setScanning(false);
        setMatchCount(event.count!);
        break;
    }
  }, []);

  useEffect(() => {
    if (status !== Status.Ready || !socket) return;

    socket.on("memoryScan", handleEvent);
    return () => {
      socket.off("memoryScan", handleEvent);
    };
  }, [status, socket, handleEvent]);

  const rowVirtualizer = useVirtualizer({
    count: results.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 20,
  });

  const virtualRows = rowVirtualizer.getVirtualItems();

  const ready = status === Status.Ready && !!api;
  const canScan = ready && !scanning && !!pattern.trim() && !!toHexPattern(dataType, pattern);

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="memory-scan-split"
    >
      {/* Left: toolbar + results */}
      <ResizablePanel defaultSize="60%" minSize="30%">
        <div className="h-full flex flex-col overflow-hidden">
          {/* Toolbar */}
          <div className="flex items-center gap-2 p-2 border-b shrink-0 flex-wrap">
            <Select value={dataType} onValueChange={(v) => { if (v) setDataType(v as DataType); }}>
              <SelectTrigger className="w-28 h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hex">Hex</SelectItem>
                <SelectItem value="utf8">UTF-8</SelectItem>
                <SelectItem value="utf16">UTF-16</SelectItem>
                <SelectItem value="int8">Int8</SelectItem>
                <SelectItem value="uint8">UInt8</SelectItem>
                <SelectItem value="int16">Int16</SelectItem>
                <SelectItem value="uint16">UInt16</SelectItem>
                <SelectItem value="int32">Int32</SelectItem>
                <SelectItem value="uint32">UInt32</SelectItem>
                <SelectItem value="float">Float</SelectItem>
                <SelectItem value="double">Double</SelectItem>
              </SelectContent>
            </Select>

            <Input
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder={dataType === "hex" ? "AA BB CC ??" : "Value..."}
              className="h-8 flex-1 min-w-[120px] max-w-xs font-mono text-xs"
              onKeyDown={(e) => {
                if (e.key === "Enter" && canScan) scanMutation.mutate();
              }}
            />

            <label className="flex items-center gap-1.5 text-xs shrink-0">
              <Checkbox checked={protR} onCheckedChange={setProtR} />
              Read
            </label>
            <label className="flex items-center gap-1.5 text-xs shrink-0">
              <Checkbox checked={protW} onCheckedChange={setProtW} />
              Write
            </label>
            <label className="flex items-center gap-1.5 text-xs shrink-0">
              <Checkbox checked={protX} onCheckedChange={setProtX} />
              Execute
            </label>

            {scanning ? (
              <Button
                variant="outline"
                size="sm"
                className="h-8 px-2.5 text-xs text-red-500 hover:text-red-600"
                onClick={() => stopMutation.mutate()}
                disabled={stopMutation.isPending}
              >
                {stopMutation.isPending ? (
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
                className="h-8 px-2.5 text-xs"
                onClick={() => scanMutation.mutate()}
                disabled={!canScan || scanMutation.isPending}
              >
                {scanMutation.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Scan
              </Button>
            )}
          </div>

          {/* Status bar */}
          <div className="flex items-center gap-3 px-3 py-1.5 border-b text-xs text-muted-foreground shrink-0">
            {scanning ? (
              <>
                <span>
                  Scanning... {progress.current}/{progress.total} ranges
                </span>
                <Progress
                  value={progress.total > 0 ? (progress.current / progress.total) * 100 : 0}
                  className="flex-1 max-w-xs"
                />
              </>
            ) : (
              <span>{results.length > 0 ? "Scan complete" : "Ready"}</span>
            )}
            <span className="ml-auto">{matchCount} matches</span>
          </div>

          {/* Results list */}
          <div ref={listRef} className="flex-1 overflow-auto">
            <div
              style={{
                height: rowVirtualizer.getTotalSize(),
                width: "100%",
                position: "relative",
              }}
            >
              {virtualRows.map((virtualRow) => {
                const result = results[virtualRow.index];
                return (
                  <div
                    key={virtualRow.key}
                    className={`absolute left-0 right-0 flex items-center px-3 font-mono text-xs cursor-pointer hover:bg-muted/50 border-b border-border/50 ${
                      selectedAddress === result.address ? "bg-accent" : ""
                    }`}
                    style={{
                      height: virtualRow.size,
                      transform: `translateY(${virtualRow.start}px)`,
                    }}
                    onClick={() =>
                      setSelectedAddress(
                        selectedAddress === result.address ? null : result.address,
                      )
                    }
                  >
                    <span className="w-32 shrink-0 text-primary">
                      {result.address}
                    </span>
                    <span className="truncate text-muted-foreground">
                      {formatHexPreview(result.preview)}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </ResizablePanel>

      <ResizableHandle />

      {/* Right: detail hex dump */}
      <ResizablePanel defaultSize="40%" minSize="20%">
        {selectedAddress ? (
          <DetailPanel address={selectedAddress} />
        ) : (
          <div className="h-full flex items-center justify-center text-muted-foreground text-xs">
            Select a result to view hex dump
          </div>
        )}
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
