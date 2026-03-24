import { useState, useEffect } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";
import { formatSize } from "@/lib/explorer";

const MAX_SIZE = 50 * 1024 * 1024; // 50 MB

export interface AudioPreviewTabParams {
  path: string;
}

export function AudioPreviewTab({ params }: IDockviewPanelProps<AudioPreviewTabParams>) {
  const { pid, device } = useSession();
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fullPath = params?.path || "";

  useEffect(() => {
    if (!pid || !device || !fullPath) return;

    let revoked = false;
    const url = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;

    fetch(url)
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const length = Number(res.headers.get("content-length") || 0);
        if (length > MAX_SIZE)
          throw new Error(`File too large (${formatSize(length)}, max ${formatSize(MAX_SIZE)})`);
        return res.blob();
      })
      .then((blob) => {
        if (revoked) return;
        if (blob.size > MAX_SIZE)
          throw new Error(`File too large (${formatSize(blob.size)}, max ${formatSize(MAX_SIZE)})`);
        setBlobUrl(URL.createObjectURL(blob));
      })
      .catch((err) => {
        if (!revoked) setError(err.message || "Failed to load audio");
      });

    return () => {
      revoked = true;
      setBlobUrl((prev) => {
        if (prev) URL.revokeObjectURL(prev);
        return null;
      });
    };
  }, [pid, device, fullPath]);

  if (!pid || !device) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No session available
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-none bg-muted/50 border-b px-4 py-2">
        <span className="text-sm truncate">{fullPath}</span>
      </div>
      <div className="flex-1 overflow-auto p-4 bg-background">
        <div className="flex items-center justify-center min-h-full">
          {error ? (
            <div className="text-foreground text-center">
              <div className="text-4xl mb-2">🔇</div>
              <div>{error}</div>
              <div className="text-sm text-muted-foreground mt-2">{fullPath}</div>
            </div>
          ) : blobUrl ? (
            <audio
              src={blobUrl}
              controls
              autoPlay
              className="w-full max-w-lg"
              onError={() => setError("Failed to play audio")}
            />
          ) : (
            <div className="text-muted-foreground">Loading...</div>
          )}
        </div>
      </div>
    </div>
  );
}
