import { useEffect, useRef, useCallback, useImperativeHandle, forwardRef, memo } from "react";
import { cn } from "@/lib/utils";

const DEFAULT_MAX_LINES = 5000;
const TRIM_AMOUNT = 1000;

export interface LogViewerHandle {
  append: (text: string) => void;
  clear: () => void;
}

interface LogViewerProps {
  maxLines?: number;
  className?: string;
}

interface LogLine {
  id: number;
  text: string;
}

const LogLineComponent = memo(({ text }: { text: string }) => (
  <div className="whitespace-pre-wrap break-all font-mono text-xs leading-5 px-2">
    {text}
  </div>
));

LogLineComponent.displayName = "LogLineComponent";

export const LogViewer = forwardRef<LogViewerHandle, LogViewerProps>(
  ({ maxLines = DEFAULT_MAX_LINES, className }, ref) => {
    const containerRef = useRef<HTMLDivElement>(null);
    const linesRef = useRef<LogLine[]>([]);
    const nextIdRef = useRef(0);
    const isAutoScrollRef = useRef(true);
    const renderRequestRef = useRef<number | null>(null);
    const pendingLinesRef = useRef<LogLine[]>([]);

    const checkAutoScroll = useCallback(() => {
      const container = containerRef.current;
      if (!container) return;
      const threshold = 50;
      const isAtBottom =
        container.scrollHeight - container.scrollTop - container.clientHeight < threshold;
      isAutoScrollRef.current = isAtBottom;
    }, []);

    const scrollToBottom = useCallback(() => {
      const container = containerRef.current;
      if (container && isAutoScrollRef.current) {
        container.scrollTop = container.scrollHeight;
      }
    }, []);

    const renderLines = useCallback(() => {
      const container = containerRef.current;
      if (!container) return;

      const fragment = document.createDocumentFragment();
      for (const line of pendingLinesRef.current) {
        const div = document.createElement("div");
        div.className = "whitespace-pre-wrap break-all font-mono text-xs leading-5 px-2";
        div.textContent = line.text;
        div.dataset.lineId = String(line.id);
        fragment.appendChild(div);
      }
      container.appendChild(fragment);
      pendingLinesRef.current = [];

      // Trim DOM if over limit
      const currentLineCount = linesRef.current.length;
      if (currentLineCount > maxLines) {
        const removeCount = currentLineCount - maxLines + TRIM_AMOUNT;
        const children = container.children;
        for (let i = 0; i < removeCount && children.length > 0; i++) {
          children[0].remove();
        }
        linesRef.current = linesRef.current.slice(removeCount);
      }

      scrollToBottom();
      renderRequestRef.current = null;
    }, [maxLines, scrollToBottom]);

    const scheduleRender = useCallback(() => {
      if (renderRequestRef.current === null) {
        renderRequestRef.current = requestAnimationFrame(renderLines);
      }
    }, [renderLines]);

    const append = useCallback(
      (text: string) => {
        const lines = text.split("\n");
        const newLines: LogLine[] = [];

        for (const line of lines) {
          if (line === "" && lines.length > 1 && lines[lines.length - 1] === "") {
            continue;
          }
          newLines.push({
            id: nextIdRef.current++,
            text: line,
          });
        }

        linesRef.current.push(...newLines);
        pendingLinesRef.current.push(...newLines);
        scheduleRender();
      },
      [scheduleRender]
    );

    const clear = useCallback(() => {
      const container = containerRef.current;
      if (container) {
        container.innerHTML = "";
      }
      linesRef.current = [];
      pendingLinesRef.current = [];
      nextIdRef.current = 0;
    }, []);

    useImperativeHandle(ref, () => ({ append, clear }), [append, clear]);

    useEffect(() => {
      const container = containerRef.current;
      if (!container) return;

      container.addEventListener("scroll", checkAutoScroll);
      return () => {
        container.removeEventListener("scroll", checkAutoScroll);
        if (renderRequestRef.current !== null) {
          cancelAnimationFrame(renderRequestRef.current);
        }
      };
    }, [checkAutoScroll]);

    return (
      <div
        ref={containerRef}
        className={cn(
          "h-full w-full overflow-auto bg-background text-foreground",
          className
        )}
      />
    );
  }
);

LogViewer.displayName = "LogViewer";
