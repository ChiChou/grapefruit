import { useState, useEffect, useRef, useCallback } from "react";
import mermaid from "mermaid";

interface MermaidGraphViewProps {
  graphData: string;
}

export function MermaidGraphView({ graphData }: MermaidGraphViewProps) {
  const [error, setError] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const containerRef = useRef<HTMLDivElement>(null);
  const contentRef = useRef<HTMLDivElement>(null);
  const [isInitialized, setIsInitialized] = useState(false);

  useEffect(() => {
    mermaid.initialize({
      startOnLoad: false,
      theme: "dark",
      fontFamily: "monospace",
    });
    setIsInitialized(true);
  }, []);

  useEffect(() => {
    if (!isInitialized || !graphData) return;

    const renderGraph = async () => {
      try {
        const id = `graph-${Date.now()}`;
        const { svg } = await mermaid.render(id, graphData);
        if (contentRef.current) {
          contentRef.current.innerHTML = svg;
          setError(null);
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to render graph");
      }
    };

    renderGraph();
  }, [graphData, isInitialized]);

  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault();
    if (e.ctrlKey) {
      const delta = e.deltaY > 0 ? 0.95 : 1.05;
      setZoom((prev) => Math.max(0.1, Math.min(5, prev * delta)));
    } else {
      setPan((prev) => ({
        x: prev.x - e.deltaX,
        y: prev.y - e.deltaY,
      }));
    }
  }, []);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      if (e.button === 0) {
        setIsDragging(true);
        setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
      }
    },
    [pan],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (isDragging) {
        setPan({
          x: e.clientX - dragStart.x,
          y: e.clientY - dragStart.y,
        });
      }
    },
    [isDragging, dragStart],
  );

  const handleMouseUp = useCallback(() => {
    setIsDragging(false);
  }, []);

  useEffect(() => {
    const container = containerRef.current;
    if (container) {
      container.addEventListener("wheel", handleWheel, { passive: false });
    }
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      if (container) {
        container.removeEventListener("wheel", handleWheel);
      }
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [handleWheel, handleMouseUp]);

  const transform = `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`;

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-destructive gap-2 p-4">
        <p className="text-sm font-medium">Failed to render graph</p>
        <p className="text-xs text-muted-foreground">{error}</p>
      </div>
    );
  }

  if (!graphData) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No graph data available
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b text-xs text-muted-foreground">
        <button
          type="button"
          className="px-2 py-0.5 rounded bg-muted hover:bg-accent"
          onClick={() => setZoom((prev) => Math.min(5, prev * 1.2))}
        >
          +
        </button>
        <button
          type="button"
          className="px-2 py-0.5 rounded bg-muted hover:bg-accent"
          onClick={() => setZoom((prev) => Math.max(0.1, prev * 0.8))}
        >
          -
        </button>
        <button
          type="button"
          className="px-2 py-0.5 rounded bg-muted hover:bg-accent"
          onClick={() => {
            setZoom(1);
            setPan({ x: 0, y: 0 });
          }}
        >
          Reset
        </button>
        <span className="ml-auto">{Math.round(zoom * 100)}%</span>
        <span className="text-muted-foreground/60">
          Drag to pan · Ctrl+scroll to zoom
        </span>
      </div>
      <div
        ref={containerRef}
        className="flex-1 overflow-hidden relative bg-[#181818]"
        style={{ cursor: isDragging ? "grabbing" : "grab" }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
      >
        <div
          ref={contentRef}
          className="absolute inset-0 flex items-center justify-center"
          style={{
            transform,
            transformOrigin: "center center",
          }}
        />
      </div>
    </div>
  );
}
