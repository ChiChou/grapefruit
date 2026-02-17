import { useState, useMemo, useCallback } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";

interface XMLNodeProps {
  node: Element;
  depth: number;
  expanded: boolean;
}

function XMLNode({ node, depth, expanded: initialExpanded }: XMLNodeProps) {
  const [isOpen, setIsOpen] = useState(initialExpanded);
  const children = Array.from(node.children);
  const hasChildren = children.length > 0;

  const toggle = useCallback(() => setIsOpen((o) => !o), []);

  const attributes = Array.from(node.attributes);

  return (
    <div style={{ paddingLeft: depth > 0 ? 16 : 0 }}>
      <div
        className="flex items-start gap-1 py-0.5 group cursor-pointer hover:bg-accent/50 rounded-sm px-1"
        onClick={hasChildren ? toggle : undefined}
      >
        <span className="shrink-0 mt-0.5 w-4 h-4 flex items-center justify-center">
          {hasChildren ? (
            isOpen ? (
              <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
            ) : (
              <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
            )
          ) : (
            <span className="w-3.5" />
          )}
        </span>
        <span className="font-mono text-xs leading-5 break-all">
          <span className="text-purple-600 dark:text-purple-400">
            {"<"}
            {node.tagName}
          </span>
          {attributes.map((attr, i) => (
            <span key={i}>
              {" "}
              <span className="text-amber-700 dark:text-amber-400">
                {attr.name}
              </span>
              <span className="text-muted-foreground">=</span>
              <span className="text-green-700 dark:text-green-400">
                &quot;{attr.value}&quot;
              </span>
            </span>
          ))}
          {!hasChildren ? (
            <span className="text-purple-600 dark:text-purple-400">
              {" />"}
            </span>
          ) : (
            <span className="text-purple-600 dark:text-purple-400">
              {">"}
            </span>
          )}
        </span>
      </div>
      {hasChildren && isOpen && (
        <>
          {children.map((child, i) => (
            <XMLNode
              key={i}
              node={child}
              depth={depth + 1}
              expanded={initialExpanded}
            />
          ))}
          <div style={{ paddingLeft: depth > 0 ? 16 : 0 }}>
            <span className="font-mono text-xs leading-5 px-1 ml-5 text-purple-600 dark:text-purple-400">
              {"</"}
              {node.tagName}
              {">"}
            </span>
          </div>
        </>
      )}
    </div>
  );
}

interface XMLTreeProps {
  xml: string;
  expanded?: boolean;
}

export function XMLTree({ xml, expanded = false }: XMLTreeProps) {
  const doc = useMemo(() => {
    const parser = new DOMParser();
    return parser.parseFromString(xml, "text/xml");
  }, [xml]);

  const root = doc.documentElement;

  if (root.tagName === "parsererror") {
    return (
      <div className="p-4 text-destructive text-sm font-mono">
        Failed to parse XML: {root.textContent}
      </div>
    );
  }

  return (
    <div className="p-2">
      <XMLNode node={root} depth={0} expanded={expanded} />
    </div>
  );
}
