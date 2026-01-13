import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ChevronRight, ChevronDown, Folder, FolderOpen } from "lucide-react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";

import type { MetaData } from "../../../../agent/src/fruity/modules/fs.ts";

interface TreeNode {
  meta: MetaData;
  children: TreeNode[] | null;
  isLoading: boolean;
  isExpanded: boolean;
}

type RootType = "!" | "~";

function DirectoryTree({
  root,
  apiReady,
  loadDirectory,
  onDirectorySelect,
}: {
  root: RootType;
  apiReady: boolean;
  loadDirectory: (path: string) => Promise<MetaData[]>;
  onDirectorySelect: (path: string) => void;
}) {
  const [nodes, setNodes] = useState<TreeNode[]>([]);
  const [activePath, setActivePath] = useState<string | null>(null);

  const rootName = root === "!" ? "Bundle" : "Home";

  useEffect(() => {
    if (!apiReady) return;

    // Initialize with root node and load its children
    setNodes([
      {
        meta: {
          name: rootName,
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

    // Load root directory contents
    loadDirectory(root)
      .then((items) => {
        const dirs = items
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
              name: rootName,
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
      .catch((err) => {
        console.error("Failed to load root directory:", err);
        setNodes([
          {
            meta: {
              name: rootName,
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
  }, [apiReady, root, rootName, loadDirectory]);

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

  const toggleNode = async (path: string[]) => {
    setNodes((prev) => {
      const targetNode = getNodeAtPath(prev, path, 0);
      if (!targetNode) return prev;

      // If expanded, collapse it
      if (targetNode.isExpanded) {
        return updateNodeAtPath(prev, path, 0, (n) => ({
          ...n,
          isExpanded: false,
        }));
      }

      // If already has children, just expand
      if (targetNode.children !== null) {
        return updateNodeAtPath(prev, path, 0, (n) => ({
          ...n,
          isExpanded: true,
        }));
      }

      // Need to load children - set loading state
      return updateNodeAtPath(prev, path, 0, (n) => ({
        ...n,
        isLoading: true,
      }));
    });

    // Check if we need to load
    const targetNode = getNodeAtPath(nodes, path, 0);
    if (!targetNode || targetNode.isExpanded || targetNode.children !== null) {
      return;
    }

    // Load children
    // For root node, path is [rootName], so we load from root directly
    // For other nodes, we skip the rootName and build the path
    const isRootNode = path.length === 1 && path[0] === rootName;
    const fullPath = isRootNode ? root : `${root}/${path.slice(1).join("/")}`;
    try {
      const items = await loadDirectory(fullPath);
      const dirs = items
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
    } catch (err) {
      console.error("Failed to load directory:", err);
      setNodes((prev) =>
        updateNodeAtPath(prev, path, 0, (n) => ({
          ...n,
          children: [],
          isLoading: false,
          isExpanded: true,
        })),
      );
    }
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
    toggleNode(path);

    // Build the full path for the finder tab
    const isRootNode = path.length === 1 && path[0] === rootName;
    const fullPath = isRootNode ? root : `${root}/${path.slice(1).join("/")}`;
    onDirectorySelect(fullPath);
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

export function FilesPanel() {
  const { t } = useTranslation();
  const { api, status } = useSession();
  const { openSingletonPanel } = useDock();
  const [activeTab, setActiveTab] = useState<"bundle" | "home">("bundle");

  const apiReady = status === ConnectionStatus.Ready && !!api;

  const loadDirectory = useCallback(
    async (path: string): Promise<MetaData[]> => {
      if (!api) return [];
      const result = await api.fs.ls(path);
      return result as unknown as MetaData[];
    },
    [api],
  );

  const handleDirectorySelect = useCallback(
    (path: string) => {
      openSingletonPanel({
        id: "finder_tab",
        component: "finder",
        title: t("finder"),
        params: { path },
      });
    },
    [openSingletonPanel, t],
  );

  return (
    <div className="h-full flex flex-col">
      <Tabs
        value={activeTab}
        onValueChange={(v) => setActiveTab(v as "bundle" | "home")}
        className="h-full flex flex-col"
      >
        <div className="p-4 pb-0">
          <TabsList>
            <TabsTrigger value="bundle">{t("bundle")}</TabsTrigger>
            <TabsTrigger value="home">{t("home")}</TabsTrigger>
          </TabsList>
        </div>
        <TabsContent value="bundle" className="flex-1 overflow-hidden">
          <DirectoryTree
            root="!"
            apiReady={apiReady}
            loadDirectory={loadDirectory}
            onDirectorySelect={handleDirectorySelect}
          />
        </TabsContent>
        <TabsContent value="home" className="flex-1 overflow-hidden">
          <DirectoryTree
            root="~"
            apiReady={apiReady}
            loadDirectory={loadDirectory}
            onDirectorySelect={handleDirectorySelect}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
