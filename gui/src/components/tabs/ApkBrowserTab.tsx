import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import {
  ChevronRight,
  ChevronDown,
  Folder,
  FolderOpen,
  File,
  Download,
  Loader2,
  Package,
  RefreshCw,
} from "lucide-react";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { Status, useSession } from "@/context/SessionContext";
import { useDroidQuery } from "@/lib/queries";
import { formatSize } from "@/lib/explorer";

interface ApkInfo {
  path: string;
  name: string;
}

interface ApkEntry {
  name: string;
  dir: boolean;
  size: number | null;
  compressedSize: number | null;
}

interface TreeNode {
  name: string;
  children: TreeNode[] | null;
  isLoading: boolean;
  isExpanded: boolean;
}

function buildTreeNodes(entries: ApkEntry[]): TreeNode[] {
  return entries
    .filter((e) => e.dir)
    .map((e) => ({
      name: e.name,
      children: null,
      isLoading: false,
      isExpanded: false,
    }));
}

function updateNodeAtPath(
  nodes: TreeNode[],
  path: string[],
  idx: number,
  updater: (n: TreeNode) => TreeNode,
): TreeNode[] {
  return nodes.map((node) => {
    if (node.name !== path[idx]) return node;
    if (idx === path.length - 1) return updater(node);
    if (node.children) {
      return {
        ...node,
        children: updateNodeAtPath(node.children, path, idx + 1, updater),
      };
    }
    return node;
  });
}

// ── APK Selector (left panel) ────────────────────────────────────────

function ApkSelector({
  apks,
  selected,
  onSelect,
}: {
  apks: ApkInfo[];
  selected: string;
  onSelect: (path: string) => void;
}) {
  return (
    <div className="overflow-auto h-full">
      {apks.map((apk) => (
        <button
          key={apk.path}
          type="button"
          className={`flex items-center gap-2 w-full py-2 px-3 text-left text-sm ${
            selected === apk.path
              ? "bg-amber-100 dark:bg-amber-900"
              : "hover:bg-accent"
          }`}
          onClick={() => onSelect(apk.path)}
        >
          <Package className="h-4 w-4 shrink-0 text-amber-600" />
          <span className="truncate">{apk.name}</span>
        </button>
      ))}
    </div>
  );
}

// ── ZIP Directory Tree (middle panel) ────────────────────────────────

function ZipTree({
  nodes,
  activePath,
  onNodeClick,
}: {
  nodes: TreeNode[];
  activePath: string | null;
  onNodeClick: (path: string[]) => void;
}) {
  const renderNode = (node: TreeNode, parentPath: string[], depth: number) => {
    const currentPath = [...parentPath, node.name];
    const pathStr = currentPath.join("/");
    const isActive = activePath === pathStr;

    return (
      <div key={node.name}>
        <button
          type="button"
          className={`flex items-center w-full py-1 px-2 text-left ${
            isActive ? "bg-amber-100 dark:bg-amber-900" : "hover:bg-accent"
          }`}
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          onClick={() => onNodeClick(currentPath)}
        >
          <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
            {node.isLoading ? (
              <Spinner className="size-3" />
            ) : node.isExpanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </span>
          {node.isExpanded ? (
            <FolderOpen className="w-4 h-4 mr-2 shrink-0 text-yellow-500" />
          ) : (
            <Folder className="w-4 h-4 mr-2 shrink-0 text-yellow-500" />
          )}
          <span className="text-sm truncate">{node.name}</span>
        </button>
        {node.isExpanded && node.children && (
          <div>
            {node.children.map((child) =>
              renderNode(child, currentPath, depth + 1),
            )}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="overflow-auto h-full">
      {nodes.map((node) => renderNode(node, [], 0))}
    </div>
  );
}

// ── File List (right panel) ──────────────────────────────────────────

function ZipFileTable({
  entries,
  isLoading,
  currentPath,
  onNavigate,
  onDownload,
  onRefresh,
}: {
  entries: ApkEntry[];
  isLoading: boolean;
  currentPath: string;
  onNavigate: (name: string) => void;
  onDownload: (name: string) => void;
  onRefresh?: () => void;
}) {
  const { t } = useTranslation();

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin mr-2" />
          {t("loading")}
        </div>
        {currentPath && (
          <div className="px-2 py-1 text-xs text-muted-foreground border-t">
            {currentPath || "/"}
          </div>
        )}
      </div>
    );
  }

  if (entries.length === 0) {
    return (
      <div className="flex flex-col h-full">
        {onRefresh && (
          <div className="flex items-center gap-2 px-2 py-1 border-b">
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={onRefresh}
            >
              <RefreshCw className="h-3 w-3" />
            </Button>
          </div>
        )}
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          {t("empty_directory")}
        </div>
        <div className="px-2 py-1 text-xs text-muted-foreground border-t">
          {currentPath || "/"}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {onRefresh && (
        <div className="flex items-center gap-2 px-2 py-1 border-b shrink-0">
          <div className="flex items-center gap-2 ml-auto">
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={onRefresh}
            >
              <RefreshCw className="h-3 w-3" />
            </Button>
          </div>
        </div>
      )}
      <div className="flex-1 overflow-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8"></TableHead>
              <TableHead>{t("name")}</TableHead>
              <TableHead className="w-12"></TableHead>
              <TableHead className="w-24 text-right">{t("size")}</TableHead>
              <TableHead className="w-32 text-right">
                {t("compressed_size")}
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {entries.map((entry) => (
              <TableRow key={entry.name} className="group">
                <TableCell>
                  {entry.dir ? (
                    <Folder className="w-4 h-4 text-yellow-500" />
                  ) : (
                    <File className="w-4 h-4 text-muted-foreground" />
                  )}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  {entry.dir ? (
                    <button
                      type="button"
                      onClick={() => onNavigate(entry.name)}
                      className="hover:text-amber-600 dark:hover:text-amber-400 hover:underline"
                    >
                      {entry.name}
                    </button>
                  ) : (
                    <span>{entry.name}</span>
                  )}
                </TableCell>
                <TableCell>
                  {!entry.dir && (
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => onDownload(entry.name)}
                      title={t("download")}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  )}
                </TableCell>
                <TableCell className="text-right text-sm">
                  {entry.dir ? "-" : formatSize(entry.size)}
                </TableCell>
                <TableCell className="text-right text-sm text-muted-foreground">
                  {entry.dir ? "-" : formatSize(entry.compressedSize)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="px-2 py-1 text-xs text-muted-foreground border-t shrink-0">
        {currentPath || "/"}
      </div>
    </div>
  );
}

// ── Main Tab ─────────────────────────────────────────────────────────

export function ApkBrowserTab(_props: IDockviewPanelProps) {
  const { droid, status, pid, device } = useSession();
  const { t } = useTranslation();
  const apiReady = status === Status.Ready && !!droid;

  // Fetch APK list
  const { data: apks } = useDroidQuery(
    ["apk", "list"],
    (api) => api.apk.list(),
    { enabled: apiReady },
  );

  const [selectedApk, setSelectedApk] = useState<string | null>(null);
  const [currentPath, setCurrentPath] = useState("");
  const [entries, setEntries] = useState<ApkEntry[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [treeNodes, setTreeNodes] = useState<TreeNode[]>([]);
  const [activeTreePath, setActiveTreePath] = useState<string | null>(null);
  const nodesRef = useRef(treeNodes);
  nodesRef.current = treeNodes;

  // Auto-select first APK
  useEffect(() => {
    if (apks && apks.length > 0 && !selectedApk) {
      setSelectedApk(apks[0].path);
    }
  }, [apks, selectedApk]);

  const loadEntries = useCallback(
    async (apkPath: string, internalPath: string) => {
      if (!droid) return { entries: [] as ApkEntry[] };
      const result = await droid.apk.ls(apkPath, internalPath);
      return result;
    },
    [droid],
  );

  // Load root when APK is selected
  useEffect(() => {
    if (!selectedApk || !apiReady) return;
    setIsLoading(true);
    setCurrentPath("");
    setActiveTreePath(null);
    loadEntries(selectedApk, "")
      .then((result) => {
        setEntries(result.entries);
        setTreeNodes(buildTreeNodes(result.entries));
      })
      .catch(() => {
        setEntries([]);
        setTreeNodes([]);
      })
      .finally(() => setIsLoading(false));
  }, [selectedApk, apiReady, loadEntries]);

  const navigateTo = useCallback(
    (internalPath: string) => {
      if (!selectedApk) return;
      setIsLoading(true);
      setCurrentPath(internalPath);
      loadEntries(selectedApk, internalPath)
        .then((result) => {
          setEntries(result.entries);
        })
        .catch(() => setEntries([]))
        .finally(() => setIsLoading(false));
    },
    [selectedApk, loadEntries],
  );

  const handleNavigate = useCallback(
    (folderName: string) => {
      const newPath = currentPath ? `${currentPath}/${folderName}` : folderName;
      navigateTo(newPath);

      // Update tree: expand and sync
      const segments = newPath.split("/");
      setActiveTreePath(segments.join("/"));

      // Ensure parent nodes are expanded and load children
      (async () => {
        for (let i = 0; i < segments.length; i++) {
          const pathSoFar = segments.slice(0, i + 1);
          const node = getNodeAtPath(nodesRef.current, pathSoFar, 0);
          if (!node) break;

          if (node.children === null && selectedApk) {
            const internalPath = pathSoFar.join("/");
            try {
              const result = await loadEntries(selectedApk, internalPath);
              setTreeNodes((prev) =>
                updateNodeAtPath(prev, pathSoFar, 0, (n) => ({
                  ...n,
                  children: buildTreeNodes(result.entries),
                  isLoading: false,
                  isExpanded: true,
                })),
              );
            } catch {
              break;
            }
          } else {
            setTreeNodes((prev) =>
              updateNodeAtPath(prev, pathSoFar, 0, (n) => ({
                ...n,
                isExpanded: true,
              })),
            );
          }
          // Allow state to settle
          await new Promise((r) => setTimeout(r, 0));
        }
      })();
    },
    [currentPath, selectedApk, loadEntries, navigateTo],
  );

  const handleTreeNodeClick = useCallback(
    (path: string[]) => {
      const pathStr = path.join("/");
      setActiveTreePath(pathStr);

      const internalPath = path.join("/");
      navigateTo(internalPath);

      const node = getNodeAtPath(nodesRef.current, path, 0);
      if (!node) return;

      if (node.isExpanded) {
        setTreeNodes((prev) =>
          updateNodeAtPath(prev, path, 0, (n) => ({
            ...n,
            isExpanded: false,
          })),
        );
        return;
      }

      if (node.children !== null) {
        setTreeNodes((prev) =>
          updateNodeAtPath(prev, path, 0, (n) => ({
            ...n,
            isExpanded: true,
          })),
        );
        return;
      }

      // Load children
      if (!selectedApk) return;
      setTreeNodes((prev) =>
        updateNodeAtPath(prev, path, 0, (n) => ({
          ...n,
          isLoading: true,
        })),
      );

      loadEntries(selectedApk, internalPath)
        .then((result) => {
          setTreeNodes((prev) =>
            updateNodeAtPath(prev, path, 0, (n) => ({
              ...n,
              children: buildTreeNodes(result.entries),
              isLoading: false,
              isExpanded: true,
            })),
          );
        })
        .catch(() => {
          setTreeNodes((prev) =>
            updateNodeAtPath(prev, path, 0, (n) => ({
              ...n,
              children: [],
              isLoading: false,
              isExpanded: true,
            })),
          );
        });
    },
    [selectedApk, loadEntries, navigateTo],
  );

  const handleDownload = useCallback(
    (fileName: string) => {
      if (pid === undefined || !selectedApk) return;
      const entryPath = currentPath ? `${currentPath}/${fileName}` : fileName;
      const url = new URL(window.location.href);
      url.pathname = `/api/apk-entry/${device}/${pid}`;
      url.searchParams.set("apk", selectedApk);
      url.searchParams.set("entry", entryPath);
      location.replace(url.toString());
    },
    [pid, device, selectedApk, currentPath],
  );

  const hasMultipleApks = apks && apks.length > 1;

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      autoSaveId="apk-browser-split"
    >
      {hasMultipleApks && (
        <>
          <ResizablePanel defaultSize="15%" minSize="10%" maxSize="30%">
            <div className="h-full flex flex-col">
              <div className="px-3 py-2 text-xs font-medium text-muted-foreground border-b">
                {t("apk_list")}
              </div>
              <ApkSelector
                apks={apks}
                selected={selectedApk || ""}
                onSelect={(path) => {
                  setSelectedApk(path);
                  setCurrentPath("");
                  setEntries([]);
                  setTreeNodes([]);
                  setActiveTreePath(null);
                }}
              />
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
        </>
      )}
      <ResizablePanel
        defaultSize={hasMultipleApks ? "25%" : "20%"}
        minSize="10%"
        maxSize="50%"
      >
        <div className="h-full flex flex-col">
          <div className="px-3 py-2 text-xs font-medium text-muted-foreground border-b">
            {t("directories")}
          </div>
          {/* Root entry */}
          <div className="overflow-auto flex-1">
            <button
              type="button"
              className={`flex items-center w-full py-1 px-2 text-left ${
                activeTreePath === null && currentPath === ""
                  ? "bg-amber-100 dark:bg-amber-900"
                  : "hover:bg-accent"
              }`}
              onClick={() => {
                setActiveTreePath(null);
                navigateTo("");
              }}
            >
              <Package className="w-4 h-4 mr-2 shrink-0 text-amber-600" />
              <span className="text-sm truncate">/</span>
            </button>
            <ZipTree
              nodes={treeNodes}
              activePath={activeTreePath}
              onNodeClick={handleTreeNodeClick}
            />
          </div>
        </div>
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize={hasMultipleApks ? "60%" : "80%"}>
        <ZipFileTable
          entries={entries}
          isLoading={isLoading}
          currentPath={currentPath}
          onNavigate={handleNavigate}
          onDownload={handleDownload}
          onRefresh={
            selectedApk ? () => navigateTo(currentPath) : undefined
          }
        />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

function getNodeAtPath(
  nodes: TreeNode[],
  path: string[],
  idx: number,
): TreeNode | null {
  const node = nodes.find((n) => n.name === path[idx]);
  if (!node) return null;
  if (idx === path.length - 1) return node;
  if (!node.children) return null;
  return getNodeAtPath(node.children, path, idx + 1);
}
