import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import dagre from "@dagrejs/dagre";

export interface CFGNode {
  id: string;
  label: string;
  lines: string[];
}

export interface CFGEdge {
  from: string;
  to: string;
  type: "true" | "false" | "unconditional";
}

interface CFGViewProps {
  nodes: CFGNode[];
  edges: CFGEdge[];
}

const CHAR_W = 7.2;
const LINE_H = 16;
const PAD_X = 12;
const PAD_Y = 8;
const LABEL_H = 20;

function measureNode(node: CFGNode) {
  const maxLen = Math.max(
    node.label.length,
    ...node.lines.map((l) => l.length),
  );
  const w = Math.max(maxLen * CHAR_W + PAD_X * 2, 80);
  const h = LABEL_H + node.lines.length * LINE_H + PAD_Y * 2;
  return { w, h };
}

const EDGE_COLORS: Record<CFGEdge["type"], string> = {
  true: "var(--r2-c32)",
  false: "var(--r2-c31)",
  unconditional: "var(--r2-c90)",
};

function edgePath(points: Array<{ x: number; y: number }>): string {
  if (points.length === 0) return "";
  const [first, ...rest] = points;
  let d = `M ${first.x} ${first.y}`;
  for (const p of rest) d += ` L ${p.x} ${p.y}`;
  return d;
}

function arrowHead(
  points: Array<{ x: number; y: number }>,
  color: string,
): React.JSX.Element | null {
  if (points.length < 2) return null;
  const to = points[points.length - 1];
  const from = points[points.length - 2];
  const angle = Math.atan2(to.y - from.y, to.x - from.x);
  const size = 6;
  const x1 = to.x - size * Math.cos(angle - Math.PI / 6);
  const y1 = to.y - size * Math.sin(angle - Math.PI / 6);
  const x2 = to.x - size * Math.cos(angle + Math.PI / 6);
  const y2 = to.y - size * Math.sin(angle + Math.PI / 6);
  return (
    <polygon points={`${to.x},${to.y} ${x1},${y1} ${x2},${y2}`} fill={color} />
  );
}

export function CFGView({ nodes, edges }: CFGViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const layout = useMemo(() => {
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "TB", nodesep: 30, ranksep: 40, marginx: 20, marginy: 20 });
    g.setDefaultEdgeLabel(() => ({}));

    for (const node of nodes) {
      const { w, h } = measureNode(node);
      g.setNode(node.id, { width: w, height: h });
    }
    for (const edge of edges) {
      g.setEdge(edge.from, edge.to, { type: edge.type });
    }

    dagre.layout(g);

    const laidOutNodes = nodes.map((node) => {
      const n = g.node(node.id);
      const { w, h } = measureNode(node);
      return { ...node, x: n.x - w / 2, y: n.y - h / 2, w, h };
    });

    const laidOutEdges = edges.map((edge) => {
      const e = g.edge(edge.from, edge.to);
      return { ...edge, points: e.points as Array<{ x: number; y: number }> };
    });

    const graphInfo = g.graph();
    const totalW = (graphInfo.width ?? 800) + 40;
    const totalH = (graphInfo.height ?? 600) + 40;

    return { nodes: laidOutNodes, edges: laidOutEdges, width: totalW, height: totalH };
  }, [nodes, edges]);

  useEffect(() => {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const scaleX = rect.width / layout.width;
    const scaleY = rect.height / layout.height;
    const fit = Math.min(scaleX, scaleY) * 0.95;
    setZoom(fit);
    setPan({
      x: (rect.width - layout.width * fit) / 2,
      y: (rect.height - layout.height * fit) / 2,
    });
  }, [layout]);

  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) {
      const delta = e.deltaY > 0 ? 0.92 : 1.08;
      setZoom((prev) => Math.max(0.05, Math.min(5, prev * delta)));
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
        setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
      }
    },
    [isDragging, dragStart],
  );

  const handleMouseUp = useCallback(() => setIsDragging(false), []);

  useEffect(() => {
    const el = containerRef.current;
    if (el) el.addEventListener("wheel", handleWheel, { passive: false });
    window.addEventListener("mouseup", handleMouseUp);
    return () => {
      if (el) el.removeEventListener("wheel", handleWheel);
      window.removeEventListener("mouseup", handleMouseUp);
    };
  }, [handleWheel, handleMouseUp]);

  if (nodes.length === 0) {
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
          onClick={() => setZoom((prev) => Math.max(0.05, prev * 0.8))}
        >
          -
        </button>
        <button
          type="button"
          className="px-2 py-0.5 rounded bg-muted hover:bg-accent"
          onClick={() => {
            if (!containerRef.current) return;
            const rect = containerRef.current.getBoundingClientRect();
            const scaleX = rect.width / layout.width;
            const scaleY = rect.height / layout.height;
            const fit = Math.min(scaleX, scaleY) * 0.95;
            setZoom(fit);
            setPan({
              x: (rect.width - layout.width * fit) / 2,
              y: (rect.height - layout.height * fit) / 2,
            });
          }}
        >
          Fit
        </button>
        <span className="ml-auto">{Math.round(zoom * 100)}%</span>
        <span className="text-muted-foreground/60">
          Drag to pan · Ctrl+scroll to zoom
        </span>
      </div>
      <div
        ref={containerRef}
        className="flex-1 overflow-hidden relative"
        style={{ cursor: isDragging ? "grabbing" : "grab", background: "var(--r2-cfg-canvas)" }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
      >
        <svg
          width={layout.width}
          height={layout.height}
          style={{
            transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
            transformOrigin: "0 0",
            position: "absolute",
          }}
        >
          {layout.edges.map((edge, i) => {
            const color = EDGE_COLORS[edge.type];
            return (
              <g key={i}>
                <path
                  d={edgePath(edge.points)}
                  fill="none"
                  stroke={color}
                  strokeWidth={1.5}
                />
                {arrowHead(edge.points, color)}
              </g>
            );
          })}
          {layout.nodes.map((node) => (
            <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
              <rect
                width={node.w}
                height={node.h}
                rx={4}
                fill="var(--r2-cfg-node)"
                stroke="var(--r2-cfg-border)"
                strokeWidth={1}
              />
              <text
                x={PAD_X}
                y={LABEL_H - 4}
                fill="var(--r2-cfg-label)"
                fontSize={12}
                fontFamily="ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"
                fontWeight={600}
              >
                {node.label}
              </text>
              <line x1={0} y1={LABEL_H} x2={node.w} y2={LABEL_H} stroke="var(--r2-cfg-border)" strokeWidth={0.5} />
              {node.lines.map((line, i) => (
                <text
                  key={i}
                  x={PAD_X}
                  y={LABEL_H + PAD_Y + (i + 1) * LINE_H - 3}
                  fill="var(--r2-cfg-text)"
                  fontSize={11}
                  fontFamily="ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"
                >
                  {line}
                </text>
              ))}
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
