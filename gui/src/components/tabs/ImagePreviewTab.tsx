import { useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";
import { ZoomIn, ZoomOut } from "lucide-react";
import { Button } from "@/components/ui/button";

export interface ImagePreviewTabParams {
  path: string;
}

export function ImagePreviewTab({ params }: IDockviewPanelProps<ImagePreviewTabParams>) {
  const { pid, device } = useSession();
  const [zoom, setZoom] = useState(100);

  const fullPath = params?.path || "";

  if (!pid || !device) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No session available
      </div>
    );
  }

  const imageUrl = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;

  return (
    <div className="flex flex-col h-full">
      <div className="flex-none bg-muted/50 border-b px-4 py-2 flex items-center justify-between">
        <span className="text-sm truncate">{fullPath}</span>
        <div className="flex items-center gap-2 ml-4">
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => setZoom((z) => Math.max(25, z - 10))}
            disabled={zoom <= 25}
          >
            <ZoomOut className="h-4 w-4" />
          </Button>
          <input
            type="range"
            min="25"
            max="200"
            value={zoom}
            onChange={(e) => setZoom(Number(e.target.value))}
            className="w-32 h-2 bg-input rounded-lg appearance-none cursor-pointer accent-primary"
          />
          <span className="text-sm w-12 text-right">{zoom}%</span>
          <Button
            variant="ghost"
            size="icon"
            className="h-8 w-8"
            onClick={() => setZoom((z) => Math.min(200, z + 10))}
            disabled={zoom >= 200}
          >
            <ZoomIn className="h-4 w-4" />
          </Button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-4 bg-background">
        <div className="flex items-center justify-center min-h-full">
          <img
            src={imageUrl}
            alt={fullPath}
            style={{ transform: `scale(${zoom / 100})` }}
            className="max-w-none transition-transform duration-75"
            onError={(e) => {
              e.currentTarget.style.display = "none";
              e.currentTarget.parentElement!.innerHTML = `
                <div class="text-foreground text-center">
                  <div class="text-4xl mb-2">🖼️</div>
                  <div>Failed to load image</div>
                  <div class="text-sm text-muted-foreground mt-2">${fullPath}</div>
                </div>
              `;
            }}
          />
        </div>
      </div>
    </div>
  );
}
