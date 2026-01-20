import { useCallback, useEffect, useState } from "react";
import type { IDockviewPanelProps } from "dockview";

import { Status, useSession } from "@/context/SessionContext";
import HexView, { type Stride } from "@/components/HexView";

export interface HexPreviewTabParams {
  path: string;
}

export function HexPreviewTab({
  params,
}: IDockviewPanelProps<HexPreviewTabParams>) {
  const { api, status, device, pid } = useSession();
  const [content, setContent] = useState<Uint8Array | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stride, setStride] = useState<Stride>(16);
  const fullPath = params?.path || "";

  const fileUrl = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;

  const loadContent = useCallback(async () => {
    if (!api || status != Status.Ready || !fullPath) return;

    setIsLoading(true);
    setError(null);

    try {
      const r = await fetch(fileUrl);
      const uint8Array = await r.bytes();
      setContent(uint8Array);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load file");
      setContent(null);
    } finally {
      setIsLoading(false);
    }
  }, [api, status, fullPath, fileUrl]);

  useEffect(() => {
    loadContent();
  }, [loadContent]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {error}
      </div>
    );
  }

  if (!content) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No content
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 p-2 border-b">
        <span className="text-sm text-muted-foreground">Stride:</span>
        <select
          value={stride}
          onChange={(e) => setStride(Number(e.target.value) as Stride)}
          className="px-2 py-1 text-sm border rounded bg-background"
        >
          <option value={8}>8</option>
          <option value={16}>16</option>
          <option value={32}>32</option>
        </select>
      </div>
      <div className="flex-1 w-full h-full min-h-0">
        <HexView data={content} stride={stride} />
      </div>
    </div>
  );
}
