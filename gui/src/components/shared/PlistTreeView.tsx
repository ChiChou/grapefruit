import { useTranslation } from "react-i18next";
import { Tree, useBranch } from "./Tree";
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
  revision,
}: {
  node: PlistTreeNode;
  depth?: number;
  forceExpanded?: boolean;
  forceCollapsed?: boolean;
  revision: number;
}) {
  const [expanded, setExpanded] = useBranch(
    forceCollapsed ? false : (forceExpanded ?? node.expanded),
    `${forceExpanded}:${forceCollapsed}:${revision}`,
  );

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
        role="treeitem" tabIndex={-1} aria-level={depth + 1} aria-expanded={hasChildren ? expanded : undefined}
        onClick={() => { if (hasChildren) setExpanded(!expanded); }}
        className="flex items-center hover:bg-accent py-0.5 font-mono focus-visible:outline-2 focus-visible:outline-ring"
        style={{ paddingLeft: `${depth * 20 + 8}px` }}
      >
        {hasChildren ? (
          <button
            type="button" data-tree-toggle aria-hidden="true" tabIndex={-1} aria-expanded={expanded}
            onClick={e => { e.stopPropagation(); setExpanded(!expanded); }}
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
              revision={revision}
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
  revision?: number;
}

export default function PlistTreeView({ data, expanded, revision = 0 }: PlistTreeProps) {
  const { t } = useTranslation();
  const tree = buildTree(data);

  return <Tree label={t("tree")}>{tree.children ? (
    tree.children.map((child, i) => (
      <PlistNode
        key={i}
        node={child}
        revision={revision}
        forceCollapsed={!expanded}
        forceExpanded={expanded}
      />
    ))
  ) : (
    <PlistNode
      node={tree}
      revision={revision}
      forceCollapsed={!expanded}
      forceExpanded={expanded}
    />
  )}</Tree>;
}
