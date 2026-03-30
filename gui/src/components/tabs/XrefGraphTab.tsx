import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, AlertCircle } from "lucide-react";
import dagre from "@dagrejs/dagre";
import { useR2Session } from "@/lib/use-r2-session";
import { useR2 } from "@/context/R2Context";

export interface XrefGraphParams {
  address: string;
  name?: string;
}

interface XrefNode {
  id: string;
  label: string;
  addr: string;
  isCurrent: boolean;
}

interface XrefEdge {
  from: string;
  to: string;
}

const NODE_W = 180;
const NODE_H = 28;

export function XrefGraphTab({ params }: IDockviewPanelProps<XrefGraphParams>) {
  const { t } = useTranslation();
  const { cmd, isReady, error: sessionError } = useR2Session();
  const r2 = useR2();
  const address = params?.address || r2.addr;
  const name = params?.name || address;

  const [nodes, setNodes] = useState<XrefNode[]>([]);
  const [edges, setEdges] = useState<XrefEdge[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const containerRef = useRef<HTMLDivElement>(null);
  const [zoom, setZoom] = useState(1);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [isDragging, setIsDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });

  const load = useCallback(async () => {
    if (!isReady || !address) return;
    setLoading(true);
    setError(null);
    try {
      const [toRaw, fromRaw] = await Promise.all([
        cmd(`axtj @ ${address}`),
        cmd(`axfj @ ${address}`),
      ]);

      const nodeMap = new Map<string, XrefNode>();
      const edgeList: XrefEdge[] = [];

      const curId = address;
      nodeMap.set(curId, { id: curId, label: name, addr: address, isCurrent: true });

      try {
        const refs: Array<{ from: number; fcn_addr?: number; fcn_name?: string }> = JSON.parse(toRaw);
        for (const ref of refs) {
          const addr = ref.fcn_addr ? `0x${ref.fcn_addr.toString(16)}` : `0x${ref.from.toString(16)}`;
          const label = ref.fcn_name || addr;
          if (!nodeMap.has(addr)) {
            nodeMap.set(addr, { id: addr, label, addr, isCurrent: false });
          }
          edgeList.push({ from: addr, to: curId });
        }
      } catch {}

      try {
        const refs: Array<{ addr?: number; at?: number; name?: string; fcn_name?: string }> = JSON.parse(fromRaw);
        for (const ref of refs) {
          const targetAddr = ref.addr ?? ref.at ?? 0;
          const addr = `0x${targetAddr.toString(16)}`;
          const label = ref.fcn_name || ref.name || addr;
          if (!nodeMap.has(addr)) {
            nodeMap.set(addr, { id: addr, label, addr, isCurrent: false });
          }
          edgeList.push({ from: curId, to: addr });
        }
      } catch {}

      setNodes(Array.from(nodeMap.values()));
      setEdges(edgeList);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [cmd, isReady, address, name]);

  useEffect(() => { load(); }, [load]);

  const layout = useMemo(() => {
    if (nodes.length === 0) return null;
    const g = new dagre.graphlib.Graph();
    g.setGraph({ rankdir: "LR", nodesep: 20, ranksep: 60, marginx: 20, marginy: 20 });
    g.setDefaultEdgeLabel(() => ({}));

    for (const n of nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
    for (const e of edges) g.setEdge(e.from, e.to);
    dagre.layout(g);

    const laid = nodes.map((n) => {
      const pos = g.node(n.id);
      return { ...n, x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 };
    });

    const laidEdges = edges.map((e) => {
      const pts = g.edge(e.from, e.to)?.points as Array<{ x: number; y: number }> | undefined;
      return { ...e, points: pts ?? [] };
    });

    const info = g.graph();
    return {
      nodes: laid,
      edges: laidEdges,
      width: (info.width ?? 600) + 40,
      height: (info.height ?? 400) + 40,
    };
  }, [nodes, edges]);

  useEffect(() => {
    if (!layout || !containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    const fit = Math.min(rect.width / layout.width, rect.height / layout.height) * 0.9;
    setZoom(fit);
    setPan({
      x: (rect.width - layout.width * fit) / 2,
      y: (rect.height - layout.height * fit) / 2,
    });
  }, [layout]);

  const handleWheel = useCallback((e: WheelEvent) => {
    e.preventDefault();
    if (e.ctrlKey || e.metaKey) {
      setZoom((z) => Math.max(0.1, Math.min(5, z * (e.deltaY > 0 ? 0.92 : 1.08))));
    } else {
      setPan((p) => ({ x: p.x - e.deltaX, y: p.y - e.deltaY }));
    }
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (el) el.addEventListener("wheel", handleWheel, { passive: false });
    return () => { if (el) el.removeEventListener("wheel", handleWheel); };
  }, [handleWheel]);

  if (sessionError) {
    return (
      <div className="flex items-center justify-center h-full">
        <AlertCircle className="h-6 w-6 text-destructive mr-2" />
        <span className="text-xs font-mono">{sessionError}</span>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_xrefs")}
      </div>
    );
  }

  if (error || !layout) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-xs">
        {error ?? t("r2_no_results")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b text-xs text-muted-foreground">
        <span className="font-mono">{name}</span>
        <span className="ml-auto">{nodes.length} nodes · {edges.length} edges</span>
      </div>
      <div
        ref={containerRef}
        className="flex-1 overflow-hidden relative"
        style={{ cursor: isDragging ? "grabbing" : "grab", background: "var(--r2-cfg-canvas, var(--card))" }}
        onMouseDown={(e) => { if (e.button === 0) { setIsDragging(true); setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y }); } }}
        onMouseMove={(e) => { if (isDragging) setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y }); }}
        onMouseUp={() => setIsDragging(false)}
        onMouseLeave={() => setIsDragging(false)}
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
          {layout.edges.map((e, i) => {
            if (e.points.length < 2) return null;
            const d = `M ${e.points.map((p) => `${p.x} ${p.y}`).join(" L ")}`;
            return (
              <g key={i}>
                <path d={d} fill="none" stroke="var(--r2-c90, #888)" strokeWidth={1.5} markerEnd="url(#arrow)" />
              </g>
            );
          })}
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX={10} refY={5} markerWidth={6} markerHeight={6} orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--r2-c90, #888)" />
            </marker>
          </defs>
          {layout.nodes.map((n) => (
            <g
              key={n.id}
              transform={`translate(${n.x}, ${n.y})`}
              className="cursor-pointer"
              onClick={() => { if (!n.isCurrent) r2.seek(n.addr, n.label); }}
            >
              <rect
                width={NODE_W}
                height={NODE_H}
                rx={4}
                fill={n.isCurrent ? "var(--primary)" : "var(--r2-cfg-node, var(--card))"}
                stroke={n.isCurrent ? "var(--primary)" : "var(--r2-cfg-border, var(--border))"}
                strokeWidth={1}
                opacity={n.isCurrent ? 0.9 : 1}
              />
              <text
                x={NODE_W / 2}
                y={NODE_H / 2 + 4}
                textAnchor="middle"
                fill={n.isCurrent ? "var(--primary-foreground)" : "var(--r2-cfg-text, var(--foreground))"}
                fontSize={10}
                fontFamily="ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace"
              >
                {n.label.length > 24 ? `${n.label.slice(0, 22)}...` : n.label}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}
