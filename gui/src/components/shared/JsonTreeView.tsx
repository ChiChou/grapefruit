import { useState } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";

function JsonLeaf({ value }: { value: unknown }) {
  if (value === null) {
    return <span className="text-muted-foreground">null</span>;
  }
  if (value === undefined) {
    return <span className="text-muted-foreground">undefined</span>;
  }
  switch (typeof value) {
    case "string":
      return (
        <span className="text-emerald-600 dark:text-emerald-400">
          &quot;{value}&quot;
        </span>
      );
    case "number":
      return (
        <span className="text-sky-600 dark:text-sky-400">{value}</span>
      );
    case "boolean":
      return (
        <span className="text-amber-600 dark:text-amber-400">
          {String(value)}
        </span>
      );
    default:
      return (
        <span className="text-muted-foreground">{String(value)}</span>
      );
  }
}

function JsonNode({
  value,
  label,
  depth,
  defaultExpanded,
}: {
  value: unknown;
  label?: string;
  depth: number;
  defaultExpanded: number;
}) {
  const [expanded, setExpanded] = useState(depth < defaultExpanded);
  const paddingLeft = depth * 16 + 4;

  if (Array.isArray(value)) {
    const count = value.length;
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
            [
            {!expanded && (
              <span className="ml-1">
                ...{count} {count === 1 ? "item" : "items"}]
              </span>
            )}
          </span>
        </div>
        {expanded && (
          <>
            {value.map((item, i) => (
              <JsonNode
                key={i}
                value={item}
                label={`${i}`}
                depth={depth + 1}
                defaultExpanded={defaultExpanded}
              />
            ))}
            <div
              className="text-muted-foreground font-mono py-px"
              style={{ paddingLeft: paddingLeft + 20 }}
            >
              ]
            </div>
          </>
        )}
      </div>
    );
  }

  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    const count = entries.length;
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
            {"{"}
            {!expanded && (
              <span className="ml-1">
                ...{count} {count === 1 ? "key" : "keys"}
                {"}"}
              </span>
            )}
          </span>
        </div>
        {expanded && (
          <>
            {entries.map(([key, val]) => (
              <JsonNode
                key={key}
                value={val}
                label={key}
                depth={depth + 1}
                defaultExpanded={defaultExpanded}
              />
            ))}
            <div
              className="text-muted-foreground font-mono py-px"
              style={{ paddingLeft: paddingLeft + 20 }}
            >
              {"}"}
            </div>
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
      <JsonLeaf value={value} />
    </div>
  );
}

export default function JsonTreeView({
  value,
  defaultExpanded = 2,
}: {
  value: unknown;
  defaultExpanded?: number;
}) {
  return (
    <div className="text-[11px] leading-relaxed select-text">
      <JsonNode value={value} depth={0} defaultExpanded={defaultExpanded} />
    </div>
  );
}
