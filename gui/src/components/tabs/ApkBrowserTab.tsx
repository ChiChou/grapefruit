import { useCallback, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
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
import { Status, useSession } from "@/context/SessionContext";
import { useDroidQuery } from "@/lib/queries";
import { formatSize } from "@/lib/explorer";

interface ApkInfo {
  path: string;
  name: string;
}

/** [name, size] */
type ApkEntry = [string, number];

// ── Tree building from flat entry list ───────────────────────────────

interface TreeNode {
  name: string;
  fullPath: string;
  children: TreeNode[];
}

/** Build a directory tree from flat APK entry paths. */
function buildTree(entries: ApkEntry[]): TreeNode[] {
  const root: TreeNode[] = [];

  for (const [name] of entries) {
    const parts = name.split("/");
    let level = root;
    let pathSoFar = "";

    // Walk/create intermediate directories
    for (let i = 0; i < parts.length - 1; i++) {
      pathSoFar = pathSoFar ? `${pathSoFar}/${parts[i]}` : parts[i];
      let existing = level.find((n) => n.name === parts[i]);
      if (!existing) {
        existing = { name: parts[i], fullPath: pathSoFar, children: [] };
        level.push(existing);
      }
      level = existing.children;
    }
  }

  // Sort recursively: alphabetical
  const sortTree = (nodes: TreeNode[]) => {
    nodes.sort((a, b) => a.name.localeCompare(b.name));
    for (const n of nodes) sortTree(n.children);
  };
  sortTree(root);
  return root;
}

/** Get direct children (files + dirs) at a given path prefix. */
function getChildren(
  entries: ApkEntry[],
  dirPath: string,
): { dirs: string[]; files: ApkEntry[] } {
  const prefix = dirPath ? dirPath + "/" : "";
  const prefixLen = prefix.length;
  const dirSet = new Set<string>();
  const files: ApkEntry[] = [];

  for (const entry of entries) {
    if (prefix && !entry[0].startsWith(prefix)) continue;
    if (entry[0] === prefix) continue;

    const rest = entry[0].slice(prefixLen);
    const slashIdx = rest.indexOf("/");

    if (slashIdx === -1) {
      files.push(entry);
    } else {
      dirSet.add(rest.slice(0, slashIdx));
    }
  }

  const dirs = [...dirSet].sort((a, b) => a.localeCompare(b));
  files.sort((a, b) => {
    const aName = a[0].split("/").pop()!;
    const bName = b[0].split("/").pop()!;
    return aName.localeCompare(bName);
  });
  return { dirs, files };
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
  expanded,
  onNodeClick,
}: {
  nodes: TreeNode[];
  activePath: string;
  expanded: Set<string>;
  onNodeClick: (fullPath: string) => void;
}) {
  const renderNode = (node: TreeNode, depth: number) => {
    const isActive = activePath === node.fullPath;
    const isExpanded = expanded.has(node.fullPath);

    return (
      <div key={node.fullPath}>
        <button
          type="button"
          className={`flex items-center w-full py-1 px-2 text-left ${
            isActive ? "bg-amber-100 dark:bg-amber-900" : "hover:bg-accent"
          }`}
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          onClick={() => onNodeClick(node.fullPath)}
        >
          <span className="w-4 h-4 mr-1 shrink-0 flex items-center justify-center">
            {node.children.length > 0 ? (
              isExpanded ? (
                <ChevronDown className="w-3 h-3" />
              ) : (
                <ChevronRight className="w-3 h-3" />
              )
            ) : null}
          </span>
          {isExpanded ? (
            <FolderOpen className="w-4 h-4 mr-2 shrink-0 text-yellow-500" />
          ) : (
            <Folder className="w-4 h-4 mr-2 shrink-0 text-yellow-500" />
          )}
          <span className="text-sm truncate">{node.name}</span>
        </button>
        {isExpanded && (
          <div>
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="overflow-auto h-full">
      {nodes.map((node) => renderNode(node, 0))}
    </div>
  );
}

// ── File List (right panel) ──────────────────────────────────────────

interface DirEntry {
  name: string;
  dir: boolean;
  size: number | null;
}

function ZipFileTable({
  items,
  isLoading,
  currentPath,
  onNavigate,
  onDownload,
  onRefresh,
}: {
  items: DirEntry[];
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

  if (items.length === 0) {
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
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((entry) => (
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

export function ApkBrowserTab() {
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
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  // Auto-select first APK
  const effectiveApk =
    selectedApk ?? (apks && apks.length > 0 ? apks[0].path : null);

  // Fetch all entries for selected APK in one shot
  const {
    data: allEntries,
    isLoading,
    refetch,
  } = useDroidQuery(
    ["apk", "entries", effectiveApk!],
    (api) => api.apk.entries(effectiveApk!),
    { enabled: apiReady && !!effectiveApk },
  );

  // Build tree from flat entries
  const treeNodes = useMemo(
    () => (allEntries ? buildTree(allEntries) : []),
    [allEntries],
  );

  // Compute current directory listing from flat entries
  const dirItems: DirEntry[] = useMemo(() => {
    if (!allEntries) return [];
    const { dirs, files } = getChildren(allEntries, currentPath);
    const result: DirEntry[] = [];
    for (const d of dirs) {
      result.push({ name: d, dir: true, size: null });
    }
    for (const [fullName, size] of files) {
      const fileName = fullName.split("/").pop()!;
      result.push({ name: fileName, dir: false, size });
    }
    return result;
  }, [allEntries, currentPath]);

  const handleNavigate = useCallback(
    (folderName: string) => {
      const newPath = currentPath
        ? `${currentPath}/${folderName}`
        : folderName;
      setCurrentPath(newPath);
      setExpanded((prev) => {
        const next = new Set(prev);
        // Expand all ancestors + the target
        const parts = newPath.split("/");
        for (let i = 1; i <= parts.length; i++) {
          next.add(parts.slice(0, i).join("/"));
        }
        return next;
      });
    },
    [currentPath],
  );

  const handleTreeNodeClick = useCallback((fullPath: string) => {
    setCurrentPath(fullPath);
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(fullPath)) {
        next.delete(fullPath);
      } else {
        // Expand all ancestors + target
        const parts = fullPath.split("/");
        for (let i = 1; i <= parts.length; i++) {
          next.add(parts.slice(0, i).join("/"));
        }
      }
      return next;
    });
  }, []);

  const handleDownload = useCallback(
    (fileName: string) => {
      if (pid === undefined || !effectiveApk) return;
      const entryPath = currentPath ? `${currentPath}/${fileName}` : fileName;
      const url = new URL(window.location.href);
      url.pathname = `/api/apk-entry/${device}/${pid}`;
      url.searchParams.set("apk", effectiveApk);
      url.searchParams.set("entry", entryPath);
      location.replace(url.toString());
    },
    [pid, device, effectiveApk, currentPath],
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
                selected={effectiveApk || ""}
                onSelect={(path) => {
                  setSelectedApk(path);
                  setCurrentPath("");
                  setExpanded(new Set());
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
          <div className="overflow-auto flex-1">
            <button
              type="button"
              className={`flex items-center w-full py-1 px-2 text-left ${
                currentPath === ""
                  ? "bg-amber-100 dark:bg-amber-900"
                  : "hover:bg-accent"
              }`}
              onClick={() => {
                setCurrentPath("");
              }}
            >
              <Package className="w-4 h-4 mr-2 shrink-0 text-amber-600" />
              <span className="text-sm truncate">/</span>
            </button>
            <ZipTree
              nodes={treeNodes}
              activePath={currentPath}
              expanded={expanded}
              onNodeClick={handleTreeNodeClick}
            />
          </div>
        </div>
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize={hasMultipleApks ? "60%" : "80%"}>
        <ZipFileTable
          items={dirItems}
          isLoading={isLoading}
          currentPath={currentPath}
          onNavigate={handleNavigate}
          onDownload={handleDownload}
          onRefresh={effectiveApk ? () => refetch() : undefined}
        />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
