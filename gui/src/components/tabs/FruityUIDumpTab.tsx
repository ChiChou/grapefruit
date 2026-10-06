import { useState, useCallback, useEffect, useMemo, useRef } from "react";
import { useTranslation } from "react-i18next";
import { useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { RefreshCw, ChevronsDownUp, ChevronsUpDown } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { ResizablePanelGroup, ResizablePanel, ResizableHandle } from "@/components/ui/resizable";
import { ButtonGroup } from "@/components/ui/button-group";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";
import { useFruityQuery, useFruityMutation, useQueryClient } from "@/lib/queries";

import { Tree, useBranch } from "@/components/shared/Tree";
import { UIPreview, UIEditor } from "./UIPreview";

import type { UIDumpNode, UIChanges } from "@agent/fruity/modules/ui";

const MODE_KEY = "ui-inspector-mode";

interface TreeNodeProps {
  node: UIDumpNode;
  depth?: number;
  defaultExpanded: boolean;
  version: number;
  hovered: string | null;
  selected?: string;
  path: Set<string>;
  matches: Set<string> | null;
  onHover: (node: UIDumpNode | null) => void;
  onSelect: (node: UIDumpNode) => void;
}

function TreeNode(props: TreeNodeProps) {
  const { node, depth = 0, defaultExpanded, version, hovered, selected, path, matches, onHover, onSelect } = props;
  const [expanded, setExpanded] = useBranch(defaultExpanded, String(version));
  const row = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (path.has(node.id)) setExpanded(true);
  }, [path, node.id, setExpanded]);
  useEffect(() => {
    if (selected === node.id) row.current?.scrollIntoView({ block: "nearest" });
  }, [selected, node.id]);
  useEffect(() => {
    if (matches?.has(node.id)) setExpanded(true);
  }, [matches, node.id, setExpanded]);
  if (matches && !matches.has(node.id)) return null;
  const children = !!node.children?.length;
  const open = expanded;
  return <li className="list-none text-xs">
    <div ref={row} data-ui-node={node.id} data-selected={selected === node.id} data-hovered={hovered === node.id}
      role="treeitem" tabIndex={-1} aria-level={depth + 1} aria-selected={selected === node.id} aria-expanded={children ? open : undefined}
      title={node.description || node.clazz}
      className={`flex items-center gap-1 py-1 pr-2 cursor-pointer border-l-2 focus-visible:outline-2 focus-visible:outline-cyan-500 focus-visible:-outline-offset-2 ${selected === node.id ? "border-amber-500 bg-amber-500/15" : hovered === node.id ? "border-cyan-500 bg-cyan-500/15" : "border-transparent"} ${node.hidden ? "opacity-50" : ""}`}
      style={{ paddingLeft: depth * 14 + 4 }}
      onClick={() => onSelect(node)}
      onFocus={() => onHover(node)} onBlur={() => onHover(null)}
      onMouseEnter={() => onHover(node)} onMouseLeave={() => onHover(null)}>
      <button data-tree-toggle aria-hidden="true" type="button" tabIndex={-1} aria-label={node.clazz} aria-expanded={children ? open : undefined}
        className="shrink-0 w-4 text-muted-foreground" disabled={!children}
        onClick={e => { e.stopPropagation(); setExpanded(v => !v); }}>{children ? open ? "−" : "+" : "·"}</button>
      <span className="font-mono truncate min-w-0">{node.clazz}</span>
      {node.text !== undefined && <span className="text-muted-foreground truncate">{node.text}</span>}
    </div>
    {open && children && <ul>{node.children!.map(child => <TreeNode {...props} key={child.id} node={child} depth={depth + 1} />)}</ul>}
  </li>;
}

function branches(node: UIDumpNode, test: (node: UIDumpNode) => boolean, result = new Set<string>()): Set<string> {
  const child = node.children?.map(n => branches(n, test, result).has(n.id)).some(Boolean);
  if (test(node) || child) result.add(node.id);
  return result;
}

function nodeById(tree: UIDumpNode, id: string): UIDumpNode | null {
  if (tree.id === id) return tree;
  for (const child of tree.children ?? []) {
    const match = nodeById(child, id);
    if (match) return match;
  }
  return null;
}

function parentById(tree: UIDumpNode, id: string): UIDumpNode | null {
  if (tree.children?.some(child => child.id === id)) return tree;
  for (const child of tree.children ?? []) {
    const match = parentById(child, id);
    if (match) return match;
  }
  return null;
}

export function FruityUIDumpTab() {
  const { t } = useTranslation();
  const cache = useQueryClient();
  const inspector = useRef<HTMLDivElement>(null);
  const { fruity } = useSession();
  const { openFilePanel } = useDock();
  const [mode, setMode] = useState<"screenshot" | "3d">(() => {
    try {
      return localStorage.getItem(MODE_KEY) === "screenshot" ? "screenshot" : "3d";
    } catch {
      return "3d";
    }
  });
  useEffect(() => {
    try { localStorage.setItem(MODE_KEY, mode); } catch { /* Storage may be unavailable. */ }
  }, [mode]);
  const [hovered, setHovered] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selection, setSelection] = useState<UIDumpNode | null>(null);
  const [expandKey, setExpandKey] = useState(0);
  const [allExpanded, setAllExpanded] = useState(true);

  const { data, isLoading, isFetching, error, refetch } = useFruityQuery(
    ["uiDump", "preview"],
    (api) => api.ui.dump({ preview: true }),
    { refetchOnWindowFocus: false, refetchOnReconnect: false, staleTime: Infinity, retry: false },
  );

  const selected = selection;
  const parent = useMemo(() => data && selected ? parentById(data, selected.id) : null, [data, selected]);
  const stale = !!selected && (!data || selected.id.split(":")[1] !== data.id.split(":")[1]);
  const edit = useFruityMutation(
    async (api, args: { id: string; changes: UIChanges }) => {
      await api.ui.update(args.id, args.changes);
      return api.ui.dump({ preview: true, selected: args.id });
    },
    { onSuccess: (tree, args) => {
      cache.setQueryData(["fruity", "uiDump", "preview"], tree);
      setSelection(current => {
        if (current?.id !== args.id) return current;
        return tree?.selected ? nodeById(tree, tree.selected) ?? current : current;
      });
    } },
  );

  const select = (node: UIDumpNode) => {
    if (edit.isPending) return;
    if (matches && !matches.has(node.id)) setSearch("");
    setSelection(node);
    edit.reset();
  };

  const hover = useCallback((node: UIDumpNode | null) => {
    setHovered(node?.id ?? null);
  }, []);

  const path = useMemo(() => data ? branches(data, n => n.id === selected?.id) : new Set<string>(), [data, selected?.id]);
  const matches = useMemo(() => {
    const term = search.trim().toLocaleLowerCase();
    return data && term ? branches(data, n => `${n.clazz} ${n.text ?? ""} ${n.delegate?.name ?? ""}`.toLocaleLowerCase().includes(term)) : null;
  }, [data, search]);
  useEffect(() => { setHovered(null); }, [data, mode]);

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
    <div ref={inspector} className="h-full flex flex-col">

      {isFetching && <div className="px-3 py-1 text-xs text-muted-foreground">{t("ui_capturing")}</div>}
      {edit.error && <div role="alert" className="px-3 py-2 text-sm text-red-500">{edit.error.message}</div>}
      {error && (
        <div className="p-4 text-sm text-red-500 dark:text-red-400">
          {(error as Error)?.message || "Failed to dump UI"}
        </div>
      )}

      <ResizablePanelGroup orientation="horizontal" autoSaveId="ui-inspector-unified" className="flex-1 min-h-0">
        <ResizablePanel id="tree" defaultSize="28%" minSize="15%" className="flex flex-col min-h-0">
          <div className="flex flex-wrap items-center gap-1 p-2 border-b min-h-12">
            <input type="search" aria-label={t("ui_search")} placeholder={t("ui_search")}
              className="min-w-24 flex-1 h-8 rounded border px-2 text-sm" value={search} onChange={e => setSearch(e.target.value)} />
        <ButtonGroup className="shrink-0">
          <Tooltip>
            <TooltipTrigger render={<Button
                variant="ghost"
                size="icon-xs"
                aria-label={t("reload")}
                onClick={() => refetch()}
                disabled={isFetching || edit.isPending}
              />}>
                <RefreshCw
                  className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`}
                />
            </TooltipTrigger>
            <TooltipContent>{t("reload")}</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger render={<Button variant="ghost" size="icon-xs" aria-label={t("expand_all")} aria-keyshortcuts="Control+Alt+ArrowRight Meta+Alt+ArrowRight" onClick={handleExpandAll} />}>
                <ChevronsUpDown className="h-4 w-4" />
            </TooltipTrigger>
            <TooltipContent>{t("expand_all")} (Ctrl/⌘+Alt+→)</TooltipContent>
          </Tooltip>
          <Tooltip>
            <TooltipTrigger render={<Button variant="ghost" size="icon-xs" aria-label={t("collapse_all")} aria-keyshortcuts="Control+Alt+ArrowLeft Meta+Alt+ArrowLeft" onClick={handleCollapseAll} />}>
                <ChevronsDownUp className="h-4 w-4" />
            </TooltipTrigger>
            <TooltipContent>{t("collapse_all")} (Ctrl/⌘+Alt+←)</TooltipContent>
          </Tooltip>
        </ButtonGroup>
          </div>
          <ScrollArea className="flex-1 min-h-0">
            <Tree label={t("ui_hierarchy")} onExpand={handleExpandAll} onCollapse={handleCollapseAll}><ul className="py-2">
              {isLoading && !data ? <Skeleton className="h-4 m-2 w-3/4" /> : data ? <TreeNode
                version={expandKey} node={data} defaultExpanded={allExpanded} hovered={hovered} selected={selected?.id}
                path={path} matches={matches} onHover={hover} onSelect={select} /> : <li className="p-3 text-muted-foreground">{t("no_data")}</li>}
              {matches && matches.size === 0 && <li className="p-3 text-sm text-muted-foreground">{t("ui_no_matches")}</li>}
            </ul></Tree>
          </ScrollArea>
        </ResizablePanel>
        <ResizableHandle withHandle aria-label={t("ui_hierarchy")} />
        <ResizablePanel id="preview" defaultSize="72%" minSize="20%">
          {data && (mode === "3d" || data.screenshot) ? <UIPreview tree={data} mode={mode} selected={selected?.id ?? null}
            hovered={hovered} onHover={hover} onSelect={select} onModeChange={() => setMode(value => value === "3d" ? "screenshot" : "3d")} /> : <div className="p-4 text-sm text-muted-foreground">{t(isFetching ? "ui_capturing" : "no_data")}</div>}
        </ResizablePanel>
        {selected && <>
          <ResizableHandle withHandle aria-label={t("ui_properties")} />
          <ResizablePanel id="properties" defaultSize="25%" minSize="15%">
            <ScrollArea className="h-full">
              {stale && <p className="px-3 pt-2 text-xs text-muted-foreground">{t("ui_selection_stale")}</p>}
              <UIEditor parent={parent?.bounds[1] ?? data?.bounds[1] ?? selected.bounds[1]} onOpenClass={handleOpenClass} key={selected.id} node={selected} busy={edit.isPending || isFetching || stale}
                onDismiss={() => {
                  const row = inspector.current?.querySelector<HTMLElement>('[data-ui-node][data-selected="true"]') ?? inspector.current?.querySelector<HTMLElement>('[data-ui-node]');
                  row?.focus();
                  setSelection(null);
                  if (!edit.isPending) edit.reset();
                }}
                onApply={changes => edit.mutate({ id: selected.id, changes })} />
            </ScrollArea>
          </ResizablePanel>
        </>}
      </ResizablePanelGroup>
    </div>
  );
}
