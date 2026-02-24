import { useState } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";

import type { XPCNode } from "@/lib/rpc";

function XPCLeaf({ node }: { node: XPCNode }) {
  switch (node.type) {
    case "string":
      return (
        <span className="text-emerald-600 dark:text-emerald-400">
          {node.description}
        </span>
      );
    case "bool":
      return (
        <span className="text-amber-600 dark:text-amber-400">
          {String(node.description)}
        </span>
      );
    case "int64":
    case "uint64":
    case "double":
      return (
        <span className="text-sky-600 dark:text-sky-400">
          {node.description}
        </span>
      );
    case "uuid":
      return (
        <span className="text-cyan-600 dark:text-cyan-400">
          {node.description}
        </span>
      );
    case "data":
      return <span className="text-muted-foreground">{node.description}</span>;
    case "fd":
      return (
        <span className="text-orange-600 dark:text-orange-400">
          {node.description}
        </span>
      );
    case "date":
      return (
        <span className="text-rose-600 dark:text-rose-400">{node.value}</span>
      );
    case "null":
      return <span className="text-muted-foreground">null</span>;
    case "error":
      return (
        <span className="text-red-600 dark:text-red-400">
          {node.description}
        </span>
      );
    case "shmem":
      return <span className="text-muted-foreground">{node.description}</span>;
    case "endpoint":
      return <span className="text-muted-foreground">{node.description}</span>;
    case "connection":
      return <span className="text-muted-foreground">{node.description}</span>;
    default:
      return <span className="text-muted-foreground">{node.description}</span>;
  }
}

function XPCTreeNode({
  node,
  label,
  depth,
}: {
  node: XPCNode;
  label?: string;
  depth: number;
}) {
  const [expanded, setExpanded] = useState(depth < 3);
  const paddingLeft = depth * 16 + 4;

  // short description for xpc collection types
  const shorten = (str: string) => {
    const end = str.indexOf(", contents");
    return end !== -1 ? str.substring(0, end) + " }" : str;
  };

  if (node.type === "dictionary") {
    return (
      <div>
        <div
          className="flex items-center hover:bg-accent/50 py-px font-mono"
          style={{ paddingLeft }}
        >
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="p-0.5 mr-1 shrink-0"
          >
            {expanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </button>
          {label !== undefined && (
            <span className="text-blue-500 dark:text-blue-400 mr-1">
              {label}
              <span className="text-muted-foreground">: </span>
            </span>
          )}
          <span className="text-muted-foreground">
            {shorten(node.description)}
          </span>
        </div>
        {expanded && (
          <>
            {node.keys.map((key, i) => (
              <XPCTreeNode
                key={i}
                node={node.values[i]}
                label={key}
                depth={depth + 1}
              />
            ))}
            <div
              className="text-muted-foreground font-mono py-px"
              style={{ paddingLeft: paddingLeft + 20 }}
            ></div>
          </>
        )}
      </div>
    );
  }

  if (node.type === "array") {
    return (
      <div>
        <div
          className="flex items-center hover:bg-accent/50 py-px font-mono"
          style={{ paddingLeft }}
        >
          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="p-0.5 mr-1 shrink-0"
          >
            {expanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </button>
          {label !== undefined && (
            <span className="text-blue-500 dark:text-blue-400 mr-1">
              {label}
              <span className="text-muted-foreground">: </span>
            </span>
          )}
          <span className="text-muted-foreground">
            {shorten(node.description)}
          </span>
        </div>
        {expanded && (
          <>
            {node.values.map((val, i) => (
              <XPCTreeNode
                key={i}
                node={val}
                label={`${i}`}
                depth={depth + 1}
              />
            ))}
            <div
              className="text-muted-foreground font-mono py-px"
              style={{ paddingLeft: paddingLeft + 20 }}
            ></div>
          </>
        )}
      </div>
    );
  }

  // Leaf node
  return (
    <div
      className="flex items-center hover:bg-accent/50 py-px font-mono"
      style={{ paddingLeft }}
    >
      <span className="w-5 shrink-0" />
      {label !== undefined && (
        <span className="text-blue-500 dark:text-blue-400 mr-1">
          {label}
          <span className="text-muted-foreground">: </span>
        </span>
      )}
      <XPCLeaf node={node} />
    </div>
  );
}

export default function XPCTreeView({ node }: { node: XPCNode }) {
  return (
    <div className="text-[11px] leading-relaxed select-text">
      <XPCTreeNode node={node} depth={0} />
    </div>
  );
}
