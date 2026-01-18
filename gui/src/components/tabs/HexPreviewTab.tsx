import { useCallback, useEffect, useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";

export interface HexPreviewTabParams {
  path: string;
}

export function HexPreviewTab({
  params,
}: IDockviewPanelProps<HexPreviewTabParams>) {
  const { api, status } = useSession();
  const [content, setContent] = useState<Uint8Array | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fullPath = params?.path || "";
  const apiReady = status === "ready" && !!api;

  const loadContent = useCallback(async () => {
    if (!apiReady || !fullPath) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await api.fs.preview(fullPath);
      const uint8Array = new Uint8Array(result);
      setContent(uint8Array);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load file");
      setContent(null);
    } finally {
      setIsLoading(false);
    }
  }, [api, apiReady, fullPath]);

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
    <div className="h-full flex items-center justify-center text-muted-foreground">
      <span className="font-mono text-sm">{fullPath}</span>
    </div>
  );
}
