import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";
import { ChevronRight, ChevronDown, ChevronUp, FileJson } from "lucide-react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";

export interface PlistPreviewTabParams {
  path: string;
}

type PlistValue =
  | string
  | number
  | boolean
  | null
  | PlistValue[]
  | { [key: string]: PlistValue };

interface PlistTreeNode {
  key?: string;
  value: PlistValue;
  expanded: boolean;
  children?: PlistTreeNode[];
}

function isObject(value: PlistValue): value is { [key: string]: PlistValue } {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isArray(value: PlistValue): value is PlistValue[] {
  return Array.isArray(value);
}

function buildTree(
  value: PlistValue,
  key?: string,
  expanded = true,
): PlistTreeNode {
  if (isObject(value)) {
    const entries = Object.entries(value);
    const children = entries.map(([k, v]) => buildTree(v, k, expanded));
    return {
      key,
      value,
      expanded,
      children,
    };
  } else if (isArray(value)) {
    const children = value.map((v, i) => buildTree(v, `[${i}]`, expanded));
    return {
      key,
      value,
      expanded,
      children,
    };
  }
  return { key, value, expanded: true };
}

function PlistNode({
  node,
  depth = 0,
  forceExpanded,
  forceCollapsed,
}: {
  node: PlistTreeNode;
  depth?: number;
  forceExpanded?: boolean;
  forceCollapsed?: boolean;
}) {
  const [expanded, setExpanded] = useState(
    forceCollapsed ? false : (forceExpanded ?? node.expanded),
  );

  useEffect(() => {
    if (forceCollapsed) {
      setExpanded(false);
    } else if (forceExpanded !== undefined) {
      setExpanded(forceExpanded);
    }
  }, [forceExpanded, forceCollapsed]);

  const hasChildren = node.children && node.children.length > 0;

  const renderValue = (value: PlistValue): string => {
    if (value === null) return "null";
    if (typeof value === "string") {
      return `"${value}"`;
    }
    if (typeof value === "boolean") {
      return value ? "true" : "false";
    }
    return String(value);
  };

  return (
    <div>
      <div
        className="flex items-center hover:bg-gray-100 dark:hover:bg-gray-800 py-0.5 font-mono"
        style={{ paddingLeft: `${depth * 20 + 8}px` }}
      >
        {hasChildren ? (
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="p-0.5 mr-1"
          >
            {expanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </button>
        ) : (
          <span className="w-5" />
        )}
        {node.key && (
          <span className="text-blue-600 dark:text-blue-400 mr-2">
            {node.key}
          </span>
        )}
        {hasChildren ? (
          <span className="text-gray-500 text-sm">
            {isObject(node.value) ? "{" : "["}
            {!expanded && node.children && node.children.length > 0 && (
              <span className="text-gray-400 ml-2">
                ...{node.children.length} items
              </span>
            )}
            {!expanded && "}"}
          </span>
        ) : (
          <span className="text-orange-600 dark:text-orange-400 font-mono text-sm">
            {renderValue(node.value)}
          </span>
        )}
      </div>
      {expanded && hasChildren && (
        <div>
          {node.children!.map((child, i) => (
            <PlistNode
              key={i}
              node={child}
              depth={depth + 1}
              forceExpanded={forceExpanded}
              forceCollapsed={forceCollapsed}
            />
          ))}
          <div
            className="text-gray-500 text-sm"
            style={{ paddingLeft: `${depth * 20 + 8 + 20}px` }}
          >
            {isObject(node.value) ? "}" : "]"}
          </div>
        </div>
      )}
    </div>
  );
}

export function PlistPreviewTab({
  params,
}: IDockviewPanelProps<PlistPreviewTabParams>) {
  const { api, status } = useSession();
  const { t } = useTranslation();
  const [data, setData] = useState<PlistValue | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandAll, setExpandAll] = useState(false);

  const fullPath = params?.path || "";
  const apiReady = status === "ready" && !!api;

  const loadContent = useCallback(async () => {
    if (!apiReady || !fullPath) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await api.fs.plist(fullPath);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load plist");
      setData(null);
    } finally {
      setIsLoading(false);
    }
  }, [api, apiReady, fullPath]);

  useEffect(() => {
    loadContent();
  }, [loadContent]);

  const handleExpandAll = () => setExpandAll(true);
  const handleCollapseAll = () => setExpandAll(false);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        {t("loading")}
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

  if (data === null) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_content")}
      </div>
    );
  }

  const tree = buildTree(data);

  return (
    <div className="h-full flex flex-col">
      <div className="flex-none px-4 py-2 bg-muted/50 border-b flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileJson className="w-4 h-4 text-yellow-500" />
          <span className="truncate text-sm">{fullPath}</span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            className="h-8"
            onClick={handleExpandAll}
          >
            <ChevronDown className="w-4 h-4 mr-1" />
            {t("expand_all")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8"
            onClick={handleCollapseAll}
          >
            <ChevronUp className="w-4 h-4 mr-1" />
            {t("collapse_all")}
          </Button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-4">
        {tree.children ? (
          tree.children.map((child, i) => (
            <PlistNode
              key={i}
              node={child}
              forceExpanded={expandAll}
              forceCollapsed={!expandAll}
            />
          ))
        ) : (
          <PlistNode
            node={tree}
            forceExpanded={expandAll}
            forceCollapsed={!expandAll}
          />
        )}
      </div>
    </div>
  );
}
