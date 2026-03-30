import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";

export interface AudioPreviewTabParams {
  path: string;
}

export function AudioPreviewTab({ params }: IDockviewPanelProps<AudioPreviewTabParams>) {
  const { pid, device } = useSession();
  const fullPath = params?.path || "";

  if (!pid || !device) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No session available
      </div>
    );
  }

  const src = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;

  return (
    <div className="flex flex-col h-full">
      <div className="flex-none bg-muted/50 border-b px-4 py-2">
        <span className="text-sm truncate">{fullPath}</span>
      </div>
      <div className="flex-1 overflow-auto p-4 bg-background">
        <div className="flex items-center justify-center min-h-full">
          <audio src={src} controls autoPlay className="w-full max-w-lg" />
        </div>
      </div>
    </div>
  );
}
