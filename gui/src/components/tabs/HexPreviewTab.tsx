import { useCallback, useRef, useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { Download, Loader2, Search } from "lucide-react";

import { Platform, useSession } from "@/context/SessionContext";
import HexView, { type HexViewHandle, type Stride } from "@/components/shared/HexView";
import DataInspector from "@/components/shared/DataInspector";
import { PageCache } from "@/lib/hex-cache";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Input } from "@/components/ui/input";

export interface HexPreviewTabParams {
  path: string;
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function HexPreviewTab({
  params,
}: IDockviewPanelProps<HexPreviewTabParams>) {
  const { fruity, droid, platform, device, pid } = useSession();
  const fs = (platform === Platform.Droid ? droid?.fs : fruity?.fs) ?? null;
  const fullPath = params?.path || "";
  const fileName = fullPath.split("/").pop() ?? "file";

  const [stride, setStride] = useState<Stride>(16);
  const [selectedOffset, setSelectedOffset] = useState<number>(-1);
  const [cacheVersion, setCacheVersion] = useState(0);
  const [gotoValue, setGotoValue] = useState("");

  const cacheRef = useRef<PageCache | null>(null);
  const handleRef = useRef<HexViewHandle | null>(null);

  const {
    data: fileSize,
    isLoading,
    error,
  } = useQuery<number, Error>({
    queryKey: ["hexSize", fullPath],
    queryFn: () => fs!.size(fullPath),
    enabled: !!fs && !!fullPath,
  });

  // Create/recreate cache when fileSize is known
  if (fileSize != null && (!cacheRef.current || cacheRef.current.fileSize !== fileSize)) {
    cacheRef.current = new PageCache(fileSize, async (offset, length) => {
      const buf = await fs!.range(fullPath, offset, length);
      return buf;
    });
  }

  const cache = cacheRef.current;

  const getBytes = useCallback(
    (offset: number, length: number) => cache?.get(offset, length) ?? null,
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [cache, cacheVersion],
  );

  const requestBytes = useCallback(
    (offset: number, _length: number) => {
      if (!cache) return;
      const pi = cache.pageFor(offset);
      cache.fetch(pi).then(() => setCacheVersion(cache.version));
      cache.prefetch([pi - 1, pi + 1]);
    },
    [cache],
  );

  const inspectorBytes = useCallback(() => {
    if (selectedOffset < 0 || !cache) return null;
    // Try to get 8 bytes from the selected offset
    return cache.get(selectedOffset, 8);
  }, [cache, selectedOffset, cacheVersion]);

  const download = useCallback(() => {
    const url = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;
    const a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.click();
  }, [device, pid, fullPath, fileName]);

  const gotoOffset = useCallback(() => {
    const parsed = parseInt(gotoValue, 16);
    if (Number.isNaN(parsed) || !handleRef.current) return;
    const row = Math.floor(parsed / stride);
    handleRef.current.virtualizer.scrollToIndex(row, { align: "center" });
    setSelectedOffset(parsed);
  }, [gotoValue, stride]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {error.message}
      </div>
    );
  }

  if (fileSize == null) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No content
      </div>
    );
  }

  const ico = "size-3.5";
  const sep = <Separator orientation="vertical" className="h-4 mx-0.5" />;

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="flex-none h-8 px-1.5 bg-muted/50 border-b flex items-center gap-0.5">
        <Select
          value={String(stride)}
          onValueChange={(v) => setStride(Number(v) as Stride)}
        >
          <SelectTrigger className="h-6 w-16 text-xs border-none bg-transparent shadow-none px-1.5 gap-1">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="8">8</SelectItem>
            <SelectItem value="16">16</SelectItem>
            <SelectItem value="32">32</SelectItem>
          </SelectContent>
        </Select>
        {sep}
        <div className="flex items-center gap-1">
          <Search className={ico + " text-muted-foreground"} />
          <Input
            className="h-6 w-24 text-xs font-mono px-1.5"
            placeholder="0x offset"
            value={gotoValue}
            onChange={(e) => setGotoValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && gotoOffset()}
          />
        </div>
        <div className="flex-1" />
        <Tooltip>
          <TooltipTrigger render={<Button variant="ghost" className="h-7 px-1.5 gap-1 text-xs" onClick={download} />}>
            <Download className={ico} />
            Download
          </TooltipTrigger>
          <TooltipContent side="bottom" className="text-xs">Download</TooltipContent>
        </Tooltip>
      </div>

      <ResizablePanelGroup orientation="horizontal" autoSaveId="hex-editor" className="flex-1 min-h-0">
        <ResizablePanel defaultSize={75} minSize={40}>
          <HexView
            fileSize={fileSize}
            stride={stride}
            getBytes={getBytes}
            requestBytes={requestBytes}
            onSelect={setSelectedOffset}
            selectedOffset={selectedOffset}
            version={cacheVersion}
            onReady={(h) => { handleRef.current = h; }}
          />
        </ResizablePanel>
        <ResizableHandle />
        <ResizablePanel defaultSize={25} minSize={15}>
          <DataInspector bytes={inspectorBytes()} offset={selectedOffset} />
        </ResizablePanel>
      </ResizablePanelGroup>

      <div className="flex-none h-6 px-2 bg-muted/50 border-t flex items-center justify-between text-[11px] text-muted-foreground font-mono">
        <span className="truncate">{fullPath}</span>
        <span>
          {fmtSize(fileSize)}
          {cache && ` · ${cache.loadedCount}/${cache.totalPages} pages`}
        </span>
      </div>
    </div>
  );
}
