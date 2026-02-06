import { useState, useCallback, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { RefreshCw, Copy, Check, ChevronsDownUp, ChevronsUpDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ButtonGroup } from "@/components/ui/button-group";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";
import { useRpcQuery } from "@/lib/queries";

const FONT_SIZES = [0.75, 1, 1.25, 1.5] as const;

import type { UIDumpNode } from "../../../../agent/types/fruity/modules/ui";

// Tokenizer for description syntax highlighting
function* tokenize(text: string, delimiters: string): IterableIterator<string> {
  let left = 0;
  for (let i = 0; i < text.length; i++) {
    const ch = text.charAt(i);
    if (delimiters.includes(ch)) {
      if (left < i) yield text.substring(left, i);
      yield ch;
      left = i + 1;
    }
  }
  yield text.substring(left);
}

interface Token {
  type: string;
  word: string;
}

function* scan(text: string): IterableIterator<Token> {
  const delimiters = "'<>: ;=()";
  let prev: string | undefined;
  let type: string;
  const operators = "<,>;:=";
  const booleanValues = ["YES", "NO"];
  const tokens = tokenize(text, delimiters);

  for (const token of tokens) {
    if (token === "'") {
      let word = token;
      for (const next of tokens) {
        word += next;
        if (next === "'") break;
      }
      yield { type: "str", word };
      continue;
    }
    if (token.match(/^0x?[\da-fA-F]+$/)) {
      type = "hex";
    } else if (token.match(/^[\d.]+$/)) {
      type = "num";
    } else if (operators.includes(token)) {
      type = "op";
    } else if (prev === "<") {
      type = "clazz";
    } else if (booleanValues.includes(token)) {
      type = "bool";
    } else {
      type = "";
    }
    yield { type, word: token };
    prev = token;
  }
}

// Description component with syntax highlighting
function Description({ text }: { text: string }) {
  const tokens = [...scan(text)];

  const typeToClass: Record<string, string> = {
    num: "text-amber-600 dark:text-amber-400",
    str: "text-purple-600 dark:text-purple-400",
    hex: "text-yellow-600 dark:text-yellow-500",
    bool: "text-green-600 dark:text-green-500",
    op: "text-teal-600 dark:text-teal-400",
    clazz: "text-pink-600 dark:text-pink-500 cursor-pointer hover:bg-black/10 dark:hover:bg-black/20",
  };

  return (
    <span className="text-muted-foreground">
      {tokens.map((token, i) => {
        if (!token.type) return token.word;
        return (
          <span key={i} className={typeToClass[token.type] || ""}>
            {token.word}
          </span>
        );
      })}
    </span>
  );
}

interface TreeNodeProps {
  node: UIDumpNode;
  depth?: number;
  defaultExpanded?: boolean;
  onHighlight?: (node: UIDumpNode) => void;
  onDismissHighlight?: () => void;
  onOpenClass?: (className: string) => void;
}

function TreeNode({
  node,
  depth = 0,
  defaultExpanded = true,
  onHighlight,
  onDismissHighlight,
  onOpenClass,
}: TreeNodeProps) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <li className="font-mono text-xs list-none">
      <p
        className="flex items-start gap-1 py-0.5 cursor-pointer transition-colors duration-200 whitespace-nowrap hover:bg-accent"
        style={{ paddingLeft: `${(depth + 1) * 16}px` }}
        onMouseEnter={() => onHighlight?.(node)}
        onMouseLeave={() => onDismissHighlight?.()}
      >
        {hasChildren ? (
          <span
            onClick={(e) => {
              e.stopPropagation();
              setExpanded(!expanded);
            }}
            className="cursor-pointer text-muted-foreground hover:text-foreground select-none w-4"
          >
            {expanded ? "−" : "+"}
          </span>
        ) : (
          <span className="text-muted-foreground w-4">·</span>
        )}
        {node.description ? (
          <Description text={node.description} />
        ) : (
          <span className="text-amber-600 dark:text-amber-400">{node.clazz}</span>
        )}
        {node.delegate?.name && (
          <span
            className="ml-4 text-yellow-700 dark:text-yellow-200 bg-muted px-1 cursor-pointer hover:text-yellow-600 dark:hover:text-yellow-400"
            title={node.delegate.name}
            onClick={(e) => {
              e.stopPropagation();
              if (node.delegate?.name) {
                onOpenClass?.(node.delegate.name);
              }
            }}
          >
            delegate: {node.delegate.description || node.delegate.name}
          </span>
        )}
      </p>
      {expanded && hasChildren && (
        <ul>
          {node.children!.map((child, i) => (
            <TreeNode
              key={i}
              node={child}
              depth={depth + 1}
              defaultExpanded={defaultExpanded}
              onHighlight={onHighlight}
              onDismissHighlight={onDismissHighlight}
              onOpenClass={onOpenClass}
            />
          ))}
        </ul>
      )}
    </li>
  );
}

// Recursively collect descriptions from tree
function collectDescriptions(node: UIDumpNode, depth: number = 0): string[] {
  const lines: string[] = [];
  const indent = "  ".repeat(depth);
  const text = node.description || node.clazz;
  const delegate = node.delegate?.description || node.delegate?.name;
  lines.push(indent + text + (delegate ? ` [delegate: ${delegate}]` : ""));
  if (node.children) {
    for (const child of node.children) {
      lines.push(...collectDescriptions(child, depth + 1));
    }
  }
  return lines;
}

export function UIDumpTab() {
  const { t } = useTranslation();
  const { fruity } = useSession();
  const { openFilePanel } = useDock();
  const [scale, setScale] = useState(1);
  const [expandKey, setExpandKey] = useState(0);
  const [allExpanded, setAllExpanded] = useState(true);
  const [copied, setCopied] = useState(false);

  const { data, isLoading, error, refetch } = useRpcQuery(
    ["uiDump"],
    // Don't include preview (screenshots) - it's slow
    (api) => api.ui.dump(),
  );

  const handleHighlight = useCallback(
    (node: UIDumpNode) => {
      if (fruity && node.frame) {
        fruity.ui.highlight(node.frame).catch(() => {});
      }
    },
    [fruity],
  );

  const handleDismissHighlight = useCallback(() => {
    if (fruity) {
      fruity.ui.dismissHighlight().catch(() => {});
    }
  }, [fruity]);

  const handleCopy = useCallback(() => {
    if (!data) return;
    const text = collectDescriptions(data).join("\n");
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
    }).catch(() => {});
  }, [data]);

  useEffect(() => {
    if (copied) {
      const timer = setTimeout(() => setCopied(false), 2000);
      return () => clearTimeout(timer);
    }
  }, [copied]);

  useEffect(() => {
    return () => {
      fruity?.ui.dismissHighlight().catch(() => {});
    };
  }, [fruity]);

  const handleExpandAll = useCallback(() => {
    setAllExpanded(true);
    setExpandKey((k) => k + 1);
  }, []);

  const handleCollapseAll = useCallback(() => {
    setAllExpanded(false);
    setExpandKey((k) => k + 1);
  }, []);

  const handleOpenClass = useCallback(
    (className: string) => {
      openFilePanel({
        id: `class_${className}`,
        component: "classDetail",
        title: className,
        params: { className },
      });
    },
    [openFilePanel],
  );

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-3 border-b border-border">
        <ButtonGroup>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                onClick={() => refetch()}
                disabled={isLoading}
              >
                <RefreshCw
                  className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
                />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{t("reload")}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" onClick={handleExpandAll}>
                <ChevronsUpDown className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{t("expand_all")}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="outline" size="sm" onClick={handleCollapseAll}>
                <ChevronsDownUp className="h-4 w-4" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>{t("collapse_all")}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                onClick={handleCopy}
                className={copied ? "text-green-600 border-green-600 dark:text-green-400 dark:border-green-400" : ""}
              >
                {copied ? (
                  <Check className="h-4 w-4" />
                ) : (
                  <Copy className="h-4 w-4" />
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>{copied ? t("copied") : t("copy")}</TooltipContent>
          </Tooltip>
        </ButtonGroup>
        <ButtonGroup>
          {FONT_SIZES.map((s) => (
            <Button
              key={s}
              variant={scale === s ? "default" : "outline"}
              size="sm"
              onClick={() => setScale(s)}
            >
              {Math.round(s * 100)}%
            </Button>
          ))}
        </ButtonGroup>
      </div>

      {error && (
        <div className="p-4 text-sm text-red-500 dark:text-red-400">
          {(error as Error)?.message || "Failed to dump UI"}
        </div>
      )}

      <div className="flex-1 overflow-auto">
        <ScrollArea className="h-full">
          <ul
            className="p-2"
            style={{
              transform: `scale(${scale})`,
              transformOrigin: "top left",
            }}
          >
            {isLoading && !data ? (
              <div className="text-sm text-muted-foreground">{t("loading")}</div>
            ) : data ? (
              <TreeNode
                key={expandKey}
                node={data}
                defaultExpanded={allExpanded}
                onHighlight={handleHighlight}
                onDismissHighlight={handleDismissHighlight}
                onOpenClass={handleOpenClass}
              />
            ) : (
              <div className="text-sm text-muted-foreground">
                {t("no_data")}
              </div>
            )}
          </ul>
        </ScrollArea>
      </div>
    </div>
  );
}
