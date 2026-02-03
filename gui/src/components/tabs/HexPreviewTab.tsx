import { useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useQuery } from "@tanstack/react-query";

import { useSession } from "@/context/SessionContext";
import HexView, { type Stride } from "@/components/HexView";

export interface HexPreviewTabParams {
  path: string;
}

export function HexPreviewTab({
  params,
}: IDockviewPanelProps<HexPreviewTabParams>) {
  const { api, device, pid } = useSession();
  const [stride, setStride] = useState<Stride>(16);
  const fullPath = params?.path || "";

  const fileUrl = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;

  const {
    data: content,
    isLoading,
    error,
  } = useQuery<Uint8Array, Error>({
    queryKey: ["hexPreview", device, pid, fullPath],
    queryFn: async () => {
      const r = await fetch(fileUrl);
      if (!r.ok) throw new Error("Failed to load file");
      return new Uint8Array(await r.arrayBuffer());
    },
    enabled: !!api && !!fullPath,
  });

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
        {error.message}
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
