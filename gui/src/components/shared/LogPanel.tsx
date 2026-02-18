import { forwardRef, useRef, useImperativeHandle } from "react";
import { MoveDown, Save, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { LogViewer, type LogViewerHandle } from "./LogViewer";

interface LogPanelProps {
  downloadUrl: string;
  onClear: () => void;
}

export type { LogViewerHandle };

export const LogPanel = forwardRef<LogViewerHandle, LogPanelProps>(
  ({ downloadUrl, onClear }, ref) => {
    const logRef = useRef<LogViewerHandle>(null);

    useImperativeHandle(ref, () => ({
      append: (text: string) => logRef.current?.append(text),
      clear: () => logRef.current?.clear(),
      scrollToBottom: () => logRef.current?.scrollToBottom(),
    }));

    return (
      <div className="relative h-full">
        <LogViewer ref={logRef} />
        <div className="absolute bottom-4 right-4 z-10 flex gap-1">
          <Button
            variant="secondary"
            size="icon"
            className="h-8 w-8 rounded-full shadow-md"
            onClick={() => logRef.current?.scrollToBottom()}
          >
            <MoveDown className="h-4 w-4" />
          </Button>
          <Button
            variant="secondary"
            size="icon"
            className="h-8 w-8 rounded-full shadow-md"
            nativeButton={false}
            render={<a href={downloadUrl} download />}
          >
            <Save className="h-4 w-4" />
          </Button>
          <Button
            variant="destructive"
            size="icon"
            className="h-8 w-8 rounded-full shadow-md"
            onClick={() => {
              logRef.current?.clear();
              onClear();
            }}
          >
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>
    );
  },
);

LogPanel.displayName = "LogPanel";
