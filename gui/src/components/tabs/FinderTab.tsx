import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  ChevronRight,
  ChevronDown,
  Folder,
  FolderOpen,
  File,
  Pencil,
  Download,
  Trash2,
  EllipsisVertical,
} from "lucide-react";
import type { IDockviewPanelProps } from "dockview";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import type {
  MetaData,
  DirectoryListing,
} from "../../../../agent/types/fruity/modules/fs.ts";

interface TreeNode {
  meta: MetaData;
  children: TreeNode[] | null;
  isLoading: boolean;
  isExpanded: boolean;
}

type RootType = "!" | "~";

export interface FinderTabParams {
  path: string;
}

function formatSize(size: number | null): string {
  if (size === null) return "-";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024)
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function formatDate(date: Date): string {
  return new Date(date).toLocaleString();
}

// naïve file type detection based on extension
function typeFor(filename: string): string {
  const ext = filename.split(".").pop()?.toLowerCase();
  if (!ext) return "hex";
  switch (ext) {
    case "txt":
    case "md":
    case "js":
    case "css":
    case "xml":
    case "pem":
      return "text";

    case "sqlite":
    case "db":
      return "sqlite";

    case "jpeg":
    case "jpg":
    case "png":
    case "gif":
    case "tiff":
    case "tif":
    case "webp":
      return "image";

    case "xcprivacy":
    case "archiver":
    case "plist":
      return "plist";

    case "ttf":
    case "otf":
    case "woff":
    case "woff2":
      return "font";

    default:
      return "hex";
  }
}

function DirectoryTree({
  root,
  apiReady,
  loadDirectory,
  onDirectorySelect,
}: {
  root: RootType;
  apiReady: boolean;
  loadDirectory: (path: string) => Promise<DirectoryListing>;
  onDirectorySelect: (path: string) => void;
}) {
  const [nodes, setNodes] = useState<TreeNode[]>([]);
  const [activePath, setActivePath] = useState<string | null>(null);

  useEffect(() => {
    if (!apiReady) return;
    setNodes([
      {
        meta: {
          name: root,
          dir: true,
          protection: null,
          size: null,
          alias: false,
          created: new Date(),
          symlink: false,
          writable: root === "~",
        },
        children: null,
        isLoading: true,
        isExpanded: true,
      },
    ]);
    loadDirectory(root)
      .then(({ list }) => {
        const dirs = list
          .filter((item) => item.dir)
          .map((meta) => ({
            meta,
            children: null,
            isLoading: false,
            isExpanded: false,
          }));
        setNodes([
          {
            meta: {
              name: root,
              dir: true,
              protection: null,
              size: null,
              alias: false,
              created: new Date(),
              symlink: false,
              writable: root === "~",
            },
            children: dirs,
            isLoading: false,
            isExpanded: true,
          },
        ]);
      })
      .catch(() => {
        setNodes([
          {
            meta: {
              name: root,
              dir: true,
              protection: null,
              size: null,
              alias: false,
              created: new Date(),
              symlink: false,
              writable: root === "~",
            },
            children: [],
            isLoading: false,
            isExpanded: true,
          },
        ]);
      });
  }, [apiReady, root, loadDirectory]);

  const updateNodeAtPath = (
    nodes: TreeNode[],
    path: string[],
    pathIndex: number,
    updater: (node: TreeNode) => TreeNode,
  ): TreeNode[] => {
    return nodes.map((node) => {
      if (node.meta.name !== path[pathIndex]) {
        return node;
      }
      if (pathIndex === path.length - 1) {
        return updater(node);
      }
      if (node.children) {
        return {
          ...node,
          children: updateNodeAtPath(
            node.children,
            path,
            pathIndex + 1,
            updater,
          ),
        };
      }
      return node;
    });
  };

  const getNodeAtPath = (
    nodes: TreeNode[],
    path: string[],
    pathIndex: number,
  ): TreeNode | null => {
    const node = nodes.find((n) => n.meta.name === path[pathIndex]);
    if (!node) return null;
    if (pathIndex === path.length - 1) return node;
    if (!node.children) return null;
    return getNodeAtPath(node.children, path, pathIndex + 1);
  };

  const handleNodeClick = (path: string[]) => {
    const pathStr = path.join("/");
    setActivePath(pathStr);
    const targetNode = getNodeAtPath(nodes, path, 0);
    if (!targetNode) return;

    const isRootNode = path.length === 1 && path[0] === root;
    const fullPath = isRootNode ? root : `${root}/${path.slice(1).join("/")}`;

    onDirectorySelect(fullPath);

    if (targetNode.isExpanded) {
      setNodes((prev) =>
        updateNodeAtPath(prev, path, 0, (n) => ({
          ...n,
          isExpanded: false,
        })),
      );
      return;
    }

    if (targetNode.children !== null) {
      setNodes((prev) =>
        updateNodeAtPath(prev, path, 0, (n) => ({
          ...n,
          isExpanded: true,
        })),
      );
      return;
    }

    setNodes((prev) =>
      updateNodeAtPath(prev, path, 0, (n) => ({
        ...n,
        isLoading: true,
      })),
    );

    loadDirectory(fullPath)
      .then(({ list }) => {
        const dirs = list
          .filter((item) => item.dir)
          .map((meta) => ({
            meta,
            children: null,
            isLoading: false,
            isExpanded: false,
          }));
        setNodes((prev) =>
          updateNodeAtPath(prev, path, 0, (n) => ({
            ...n,
            children: dirs,
            isLoading: false,
            isExpanded: true,
          })),
        );
      })
      .catch(() => {
        setNodes((prev) =>
          updateNodeAtPath(prev, path, 0, (n) => ({
            ...n,
            children: [],
            isLoading: false,
            isExpanded: true,
          })),
        );
      });
  };

  const renderNode = (node: TreeNode, path: string[], depth: number) => {
    const currentPath = [...path, node.meta.name];
    const pathStr = currentPath.join("/");
    const isActive = activePath === pathStr;

    return (
      <div key={node.meta.name}>
        <button
          type="button"
          className={`flex items-center w-full py-1 px-2 text-left ${
            isActive
              ? "bg-blue-100 dark:bg-blue-900"
              : "hover:bg-gray-100 dark:hover:bg-gray-800"
          }`}
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          onClick={() => handleNodeClick(currentPath)}
        >
          <span className="w-4 h-4 mr-1 flex items-center justify-center">
            {node.isLoading ? (
              <span className="animate-spin text-xs">⏳</span>
            ) : node.isExpanded ? (
              <ChevronDown className="w-3 h-3" />
            ) : (
              <ChevronRight className="w-3 h-3" />
            )}
          </span>
          {node.isExpanded ? (
            <FolderOpen className="w-4 h-4 mr-2 text-yellow-500" />
          ) : (
            <Folder className="w-4 h-4 mr-2 text-yellow-500" />
          )}
          <span className="text-sm truncate">{node.meta.name}</span>
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

function FileTable({
  items,
  isLoading,
  cwd,
  onDownload,
  onPreview,
}: {
  items: MetaData[];
  isLoading: boolean;
  cwd: string;
  onDownload: (fileName: string) => void;
  onPreview: (fileName: string, type: string) => void;
}) {
  const { t } = useTranslation();

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-gray-500">
          {t("loading")}...
        </div>
        {cwd && (
          <div className="px-2 py-1 text-xs text-gray-500 border-t">{cwd}</div>
        )}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-gray-500">
          {t("empty_directory")}
        </div>
        {cwd && (
          <div className="px-2 py-1 text-xs text-gray-500 border-t">{cwd}</div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8"></TableHead>
              <TableHead>{t("name")}</TableHead>
              <TableHead className="w-32"></TableHead>
              <TableHead className="w-24 text-right">{t("size")}</TableHead>
              <TableHead className="w-48">{t("modified")}</TableHead>
              <TableHead className="w-4"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((item) => (
              <TableRow key={item.name} className="group">
                <TableCell>
                  {item.dir ? (
                    <Folder className="w-4 h-4 text-yellow-500" />
                  ) : (
                    <File className="w-4 h-4 text-gray-500" />
                  )}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  <button
                    type="button"
                    onClick={() => onPreview(item.name, typeFor(item.name))}
                    className="hover:text-blue-600 dark:hover:text-blue-400 hover:underline"
                  >
                    {item.name}
                  </button>
                </TableCell>
                <TableCell>
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => onDownload(item.name)}
                      title={t("download")}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      title={t("rename")}
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      title={t("delete")}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TableCell>
                <TableCell className="text-right text-sm">
                  {item.dir ? "-" : formatSize(item.size)}
                </TableCell>
                <TableCell className="text-sm text-gray-500">
                  {formatDate(item.created)}
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        title={t("open_with")}
                      >
                        <EllipsisVertical className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start">
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "hex")}
                      >
                        {t("hex_view")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "text")}
                      >
                        {t("text_editor")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "sqlite")}
                      >
                        {t("sqlite_editor")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "image")}
                      >
                        {t("image_preview")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "plist")}
                      >
                        {t("plist_preview")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "font")}
                      >
                        {t("font_preview")}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {cwd && (
        <div className="px-2 py-1 text-xs text-gray-500 border-t shrink-0">
          {cwd}
        </div>
      )}
    </div>
  );
}

const PREFIXES = {
  home: "~",
  bundle: "!",
} as const;

export function FinderTab({ params }: IDockviewPanelProps<FinderTabParams>) {
  const { api, status, pid, device } = useSession();
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();

  const initialPath = params?.path || PREFIXES.home;
  const initialTab = initialPath === PREFIXES.bundle ? "bundle" : "home";

  const [activeTab, setActiveTab] = useState<keyof typeof PREFIXES>(initialTab);
  const [items, setItems] = useState<MetaData[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const [fullCwd, setFullCwd] = useState<string | null>(null);
  const apiReady = status === ConnectionStatus.Ready && !!api;

  const loadDirectory = useCallback(
    async (path: string): Promise<DirectoryListing> => {
      if (!api) return { cwd: "", list: [] };
      return api.fs.ls(path);
    },
    [api],
  );

  const handleDirectorySelect = useCallback(
    (path: string) => {
      setIsLoading(true);
      loadDirectory(path)
        .then(({ cwd, list }) => {
          const data = list.filter((e) => !e.dir);
          data.sort((a, b) => a.name.localeCompare(b.name));
          setFullCwd(cwd);
          setItems(data);
        })
        .catch(() => {
          setItems([]);
        })
        .finally(() => setIsLoading(false));
    },
    [loadDirectory],
  );

  const handleDownload = useCallback(
    (fileName: string) => {
      if (pid === undefined || fullCwd === null) return;

      const url = new URL(window.location.href);
      url.pathname = `/api/download/${device}/${pid}`;
      url.searchParams.set("path", `${fullCwd}/${fileName}`);
      window.open(url.toString());
    },
    [pid, device, fullCwd],
  );

  const handlePreview = useCallback(
    (fileName: string, type: string) => {
      const fullPath = `${fullCwd}/${fileName}`;
      const panelId = `preview-${fileName}`;

      const componentMap: Record<string, string> = {
        hex: "hexPreview",
        text: "textEditor",
        sqlite: "sqliteEditor",
        image: "imagePreview",
        plist: "plistPreview",
        font: "fontPreview",
      };

      const component = componentMap[type];
      if (!component) return;

      openSingletonPanel({
        id: panelId,
        component,
        title: fileName,
        params: { path: fullPath },
      });
    },
    [fullCwd, openSingletonPanel],
  );

  useEffect(() => {
    if (!apiReady) return;
    const path = PREFIXES[activeTab];
    handleDirectorySelect(path);
  }, [apiReady, activeTab, handleDirectorySelect]);

  useEffect(() => {
    if (!apiReady || !params?.path) return;
    if (params.path === "!") {
      setActiveTab("bundle");
    } else {
      setActiveTab("home");
    }
  }, [apiReady, params?.path]);

  return (
    <ResizablePanelGroup direction="horizontal" autoSaveId="finder-split">
      <ResizablePanel defaultSize={15} minSize={5} maxSize={80}>
        <Tabs
          value={activeTab}
          onValueChange={(v) => setActiveTab(v as "bundle" | "home")}
          className="h-full flex flex-col"
        >
          <TabsList className="w-full rounded-none">
            <TabsTrigger value="home" className="flex-1">
              {t("home")}
            </TabsTrigger>
            <TabsTrigger value="bundle" className="flex-1">
              {t("bundle")}
            </TabsTrigger>
          </TabsList>
          <TabsContent value="bundle" className="flex-1 overflow-hidden mt-0">
            <DirectoryTree
              root="!"
              apiReady={apiReady}
              loadDirectory={loadDirectory}
              onDirectorySelect={handleDirectorySelect}
            />
          </TabsContent>
          <TabsContent value="home" className="flex-1 overflow-hidden mt-0">
            <DirectoryTree
              root="~"
              apiReady={apiReady}
              loadDirectory={loadDirectory}
              onDirectorySelect={handleDirectorySelect}
            />
          </TabsContent>
        </Tabs>
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize={85}>
        <FileTable
          items={items}
          isLoading={isLoading}
          cwd={fullCwd!}
          onDownload={handleDownload}
          onPreview={handlePreview}
        />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}
