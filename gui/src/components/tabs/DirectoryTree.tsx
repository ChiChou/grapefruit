import { useEffect, useState } from "react";
import { ChevronRight, ChevronDown, Folder, FolderOpen } from "lucide-react";
import type {
  TreeNode,
  RootType,
  LoadDirectoryFn,
  DirectorySelectFn,
} from "../../lib/file-explorer.ts";
import type { MetaData } from "../../../../agent/types/fruity/modules/fs.ts";

interface DirectoryTreeProps {
  root: RootType;
  apiReady: boolean;
  loadDirectory: LoadDirectoryFn;
  onDirectorySelect: DirectorySelectFn;
}

function createRootNode(root: RootType): TreeNode {
  return {
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
  };
}

function buildDirectoryNodes(list: MetaData[]): TreeNode[] {
  return list
    .filter((item) => item.dir)
    .map((meta) => ({
      meta,
      children: null,
      isLoading: false,
      isExpanded: false,
    }));
}

function updateNodeAtPath(
  nodes: TreeNode[],
  path: string[],
  pathIndex: number,
  updater: (node: TreeNode) => TreeNode,
): TreeNode[] {
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
        children: updateNodeAtPath(node.children, path, pathIndex + 1, updater),
      };
    }
    return node;
  });
}

function getNodeAtPath(
  nodes: TreeNode[],
  path: string[],
  pathIndex: number,
): TreeNode | null {
  const node = nodes.find((n) => n.meta.name === path[pathIndex]);
  if (!node) return null;
  if (pathIndex === path.length - 1) return node;
  if (!node.children) return null;
  return getNodeAtPath(node.children, path, pathIndex + 1);
}

export function DirectoryTree({
  root,
  apiReady,
  loadDirectory,
  onDirectorySelect,
}: DirectoryTreeProps) {
  const [nodes, setNodes] = useState<TreeNode[]>([]);
  const [activePath, setActivePath] = useState<string | null>(null);

  useEffect(() => {
    if (!apiReady) return;
    setNodes([createRootNode(root)]);
    loadDirectory(root)
      .then(({ list }) => {
        setNodes([
          {
            ...createRootNode(root),
            children: buildDirectoryNodes(list),
            isLoading: false,
            isExpanded: true,
          },
        ]);
      })
      .catch(() => {
        setNodes([
          {
            ...createRootNode(root),
            children: [],
            isLoading: false,
            isExpanded: true,
          },
        ]);
      });
  }, [apiReady, root, loadDirectory]);

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
        setNodes((prev) =>
          updateNodeAtPath(prev, path, 0, (n) => ({
            ...n,
            children: buildDirectoryNodes(list),
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
