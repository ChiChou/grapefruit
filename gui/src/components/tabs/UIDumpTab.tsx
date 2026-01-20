import { useEffect, useState, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Status, useSession } from "@/context/SessionContext";
import { RefreshCw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";

import type { UIDumpNode } from "../../../../agent/types/fruity/modules/ui";

interface TreeNodeProps {
  node: UIDumpNode;
  depth?: number;
  onSelect?: (node: UIDumpNode) => void;
  selectedNode?: UIDumpNode | null;
}

function TreeNode({ node, depth = 0, onSelect, selectedNode }: TreeNodeProps) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;
  const isSelected = selectedNode === node;

  return (
    <div className="font-mono text-xs">
      <div
        className={`flex items-start gap-1 hover:bg-gray-100 dark:hover:bg-gray-800 py-0.5 px-1 cursor-pointer ${
          isSelected ? "bg-blue-100 dark:bg-blue-900" : ""
        }`}
        onClick={() => onSelect?.(node)}
        style={{ paddingLeft: `${depth * 12 + 4}px` }}
      >
        {hasChildren ? (
          <button
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
            className="mt-0.5 w-3 h-3 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-700 rounded"
          >
            {expanded ? "▼" : "▶"}
          </button>
        ) : (
          <span className="w-3 h-3" />
        )}
        <span className="text-blue-600 dark:text-blue-400">{node.clazz}</span>
        {node.frame && (
          <span className="text-gray-500">
            [{String(node.frame[0][0].toFixed(0))},{" "}
            {String(node.frame[0][1].toFixed(0))};{" "}
            {String(node.frame[1][0].toFixed(0))}x
            {String(node.frame[1][1].toFixed(0))}]
          </span>
        )}
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children!.map((child, i) => (
            <TreeNode
              key={i}
              node={child}
              depth={depth + 1}
              onSelect={onSelect}
              selectedNode={selectedNode}
            />
          ))}
        </div>
      )}
    </div>
  );
}

interface UIVisualizerProps {
  node: UIDumpNode;
  onSelect?: (node: UIDumpNode) => void;
  selectedNode?: UIDumpNode | null;
}

function UIVisualizer({ node, onSelect, selectedNode }: UIVisualizerProps) {
  const renderNode = (
    n: UIDumpNode,
    depth: number = 0,
    index: number = 0,
  ): React.ReactNode => {
    const isSelected = selectedNode === n;
    if (n.preview) {
      const i = new Image();
      i.setAttribute("src", `data:image/png;base64,${n.preview}`);
      document.body.appendChild(i);
      document.body.removeChild(i);
    }
    const hasPreview = n.preview && n.preview.length > 0;
    const patternId = `preview-${depth}-${index}`;

    return (
      <g key={`${n.clazz}-${depth}-${index}`}>
        {n.frame && hasPreview && (
          <pattern
            id={patternId}
            patternUnits="userSpaceOnUse"
            x={n.frame![0][0]}
            y={n.frame![0][1]}
            width={n.frame![1][0]}
            height={n.frame![1][1]}
          >
            <image
              href={`data:image/png;base64,${n.preview}`}
              x={0}
              y={0}
              width={n.frame![1][0]}
              height={n.frame![1][1]}
              preserveAspectRatio="none"
            />
          </pattern>
        )}
        {n.frame && (
          <rect
            x={n.frame![0][0]}
            y={n.frame![0][1]}
            width={n.frame![1][0]}
            height={n.frame![1][1]}
            fill={
              hasPreview
                ? `url(#${patternId})`
                : isSelected
                  ? "rgba(59, 130, 246, 0.3)"
                  : "transparent"
            }
            stroke={isSelected ? "#3b82f6" : "#94a3b8"}
            strokeWidth={isSelected ? 2 : 1}
            fillOpacity={hasPreview ? 1 : 0.1}
            className="cursor-pointer transition-all duration-150"
            onClick={(e) => {
              e.stopPropagation();
              onSelect?.(n);
            }}
          />
        )}
        {n.frame && depth < 3 && (
          <text
            x={n.frame![0][0] + 4}
            y={n.frame![0][1] + 14}
            fontSize={10}
            fill={isSelected ? "#1d4ed8" : "#475569"}
            className="pointer-events-none"
          >
            {n.clazz}
          </text>
        )}
        {n.children?.map((child, i) => renderNode(child, depth + 1, i))}
      </g>
    );
  };

  const bounds = calculateBounds(node);

  return (
    <svg
      width={bounds.width}
      height={bounds.height}
      viewBox={`${bounds.x} ${bounds.y} ${bounds.width} ${bounds.height}`}
      className="w-full h-full bg-gray-50 dark:bg-gray-900"
    >
      <rect
        x={bounds.x}
        y={bounds.y}
        width={bounds.width}
        height={bounds.height}
        fill="transparent"
      />
      {renderNode(node)}
    </svg>
  );
}

function calculateBounds(node: UIDumpNode): {
  x: number;
  y: number;
  width: number;
  height: number;
} {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;

  const traverse = (n: UIDumpNode) => {
    if (n.frame) {
      const [point, size] = n.frame;
      minX = Math.min(minX, point[0]);
      minY = Math.min(minY, point[1]);
      maxX = Math.max(maxX, point[0] + size[0]);
      maxY = Math.max(maxY, point[1] + size[1]);
    }
    n.children?.forEach(traverse);
  };

  traverse(node);

  if (minX === Infinity) {
    minX = 0;
    minY = 0;
    maxX = 375;
    maxY = 812;
  }

  return {
    x: minX - 10,
    y: minY - 10,
    width: maxX - minX + 20,
    height: maxY - minY + 20,
  };
}

export function UIDumpTab() {
  const { t } = useTranslation();
  const { api, status } = useSession();
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<UIDumpNode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<UIDumpNode | null>(null);
  const [searchQuery, setSearchQuery] = useState("");

  const fetchData = useCallback(async () => {
    if (!api || status !== Status.Ready) return;

    setLoading(true);
    setError(null);
    try {
      const data = await api.ui.dump(true);
      console.debug(data);
      setData(data);
    } catch (err) {
      setError((err as Error)?.message || "Failed to dump UI");
    } finally {
      setLoading(false);
    }
  }, [api, status]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleSelect = useCallback(
    (node: UIDumpNode) => {
      setSelectedNode(node);
      if (api && node.frame) {
        api.ui.highlight(node.frame).catch(() => {});
      }
    },
    [api],
  );

  const filteredData =
    searchQuery && data ? filterNodes(data, searchQuery.toLowerCase()) : data;

  function filterNodes(node: UIDumpNode, query: string): UIDumpNode | null {
    const matches =
      node.clazz.toLowerCase().includes(query) ||
      node.description?.toLowerCase().includes(query);

    if (node.children) {
      const filteredChildren = node.children
        .map((child) => filterNodes(child, query))
        .filter((child): child is UIDumpNode => child !== null);

      if (matches || filteredChildren.length > 0) {
        return {
          ...node,
          children: matches ? node.children : filteredChildren,
        };
      }
    }

    return matches ? node : null;
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
            <Input
              placeholder={t("search_ui_elements")}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 w-64 h-8 text-xs"
            />
          </div>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={fetchData}
          disabled={loading || status !== Status.Ready}
        >
          <RefreshCw
            className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`}
          />
          {t("reload")}
        </Button>
      </div>

      {error && (
        <div className="p-4 text-sm text-red-500 dark:text-red-400">
          {error}
        </div>
      )}

      <div className="flex-1 overflow-hidden">
        <ResizablePanelGroup direction="horizontal">
          <ResizablePanel defaultSize={60} minSize={30}>
            <div className="h-full flex flex-col">
              <div className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-xs font-medium text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                {t("visual_preview")}
              </div>
              <div className="flex-1 overflow-auto bg-gray-50 dark:bg-gray-900 relative">
                {loading && !data ? (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    {t("loading")}
                  </div>
                ) : data ? (
                  <UIVisualizer
                    node={data}
                    onSelect={handleSelect}
                    selectedNode={selectedNode}
                  />
                ) : (
                  <div className="flex items-center justify-center h-full text-gray-500">
                    {t("no_data")}
                  </div>
                )}
              </div>
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel defaultSize={40} minSize={20}>
            <div className="h-full flex flex-col">
              <div className="px-4 py-2 bg-gray-100 dark:bg-gray-800 text-xs font-medium text-gray-500 dark:text-gray-400 border-b border-gray-200 dark:border-gray-700">
                {t("ui_hierarchy")}
              </div>
              <ScrollArea className="flex-1">
                <div className="p-2">
                  {loading && !data ? (
                    <div className="text-sm text-gray-500">Loading...</div>
                  ) : filteredData ? (
                    <TreeNode
                      node={filteredData}
                      onSelect={handleSelect}
                      selectedNode={selectedNode}
                    />
                  ) : (
                    <div className="text-sm text-gray-500">
                      {t("no_result_found")}
                    </div>
                  )}
                </div>
              </ScrollArea>
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </div>

      {selectedNode && (
        <div className="p-4 border-t border-gray-200 dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
          <div className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">
            {t("selected_element")}
          </div>
          <div className="text-sm font-mono">
            <div className="text-blue-600 dark:text-blue-400">
              {selectedNode.clazz}
            </div>
            {selectedNode.frame && (
              <div className="text-gray-600 dark:text-gray-300 mt-1">
                Frame: ({selectedNode.frame[0][0].toFixed(1)},{" "}
                {selectedNode.frame[0][1].toFixed(1)}){" "}
                {selectedNode.frame[1][0].toFixed(1)}x
                {selectedNode.frame[1][1].toFixed(1)}
              </div>
            )}
            {selectedNode.delegate?.name && (
              <div className="text-gray-600 dark:text-gray-300">
                Delegate: {selectedNode.delegate.name}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
