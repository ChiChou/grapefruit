import { useEffect, useState } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";

export type PlistValue =
  | string
  | number
  | boolean
  | null
  | PlistValue[]
  | { [key: string]: PlistValue };

export interface PlistTreeNode {
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
        className="flex items-center hover:bg-accent py-0.5 font-mono"
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
          <span className="text-amber-600 dark:text-amber-400 mr-2 text-sm after:content-[':']">
            {node.key}
          </span>
        )}
        {hasChildren ? (
          <span className="text-muted-foreground text-sm">
            {isObject(node.value) ? "{" : "["}
            {!expanded && node.children && node.children.length > 0 && (
              <span className="text-muted-foreground ml-2">
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
            className="text-muted-foreground text-sm"
            style={{ paddingLeft: `${depth * 20 + 8 + 20}px` }}
          >
            {isObject(node.value) ? "}" : "]"}
          </div>
        </div>
      )}
    </div>
  );
}

interface PlistTreeProps {
  data:
    | string
    | number
    | boolean
    | PlistValue[]
    | { [key: string]: PlistValue };
  expanded: boolean;
}

export default function PlistTreeView({ data, expanded }: PlistTreeProps) {
  const tree = buildTree(data);

  return tree.children ? (
    tree.children.map((child, i) => (
      <PlistNode
        key={i}
        node={child}
        forceCollapsed={!expanded}
        forceExpanded={expanded}
      />
    ))
  ) : (
    <PlistNode
      node={tree}
      forceCollapsed={!expanded}
      forceExpanded={expanded}
    />
  );
}
