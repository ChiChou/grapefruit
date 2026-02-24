import { useEffect, useRef, useState } from "react";
import { ChevronRight, ChevronDown, Folder, FolderOpen } from "lucide-react";
import { Spinner } from "@/components/ui/spinner";
import type {
  TreeNode,
  RootType,
  LoadDirectoryFn,
  DirectorySelectFn,
} from "@/lib/explorer.ts";
import type { MetaData } from "@agent/fruity/modules/fs";

interface DirectoryTreeProps {
  root: RootType;
  rootPath: string;
  apiReady: boolean;
  loadDirectory: LoadDirectoryFn;
  onDirectorySelect: DirectorySelectFn;
  currentPath?: string | null;
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

function absoluteToTreePath(
  absolutePath: string,
  rootPath: string,
  root: RootType,
): string[] | null {
  if (absolutePath === rootPath) return [root];
  if (!absolutePath.startsWith(rootPath + "/")) return null;
  const relative = absolutePath.slice(rootPath.length + 1);
  return [root, ...relative.split("/")];
}

export function DirectoryTree({
  root,
  rootPath,
  apiReady,
  loadDirectory,
  onDirectorySelect,
  currentPath,
}: DirectoryTreeProps) {
  const [nodes, setNodes] = useState<TreeNode[]>([]);
  const [activePath, setActivePath] = useState<string | null>(null);
  const nodesRef = useRef(nodes);
  nodesRef.current = nodes;
  const lastInternalNavRef = useRef<string | null>(null);

  useEffect(() => {
    if (!apiReady) return;
    setNodes([createRootNode(root)]);
    loadDirectory(rootPath)
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
  }, [apiReady, root, rootPath, loadDirectory]);

  // Sync tree expansion/highlight when currentPath changes externally
  // (e.g. navigating into a folder from the file list)
  useEffect(() => {
    if (!currentPath) return;

    // Skip if this navigation originated from the tree itself
    if (lastInternalNavRef.current === currentPath) {
      lastInternalNavRef.current = null;
      return;
    }
    lastInternalNavRef.current = null;

    const segments = absoluteToTreePath(currentPath, rootPath, root);
    if (!segments) return;

    // Set highlight immediately
    setActivePath(segments.join("/"));

    let cancelled = false;

    // Walk depth-by-depth, loading children as needed and expanding
    (async () => {
      for (let i = 0; i < segments.length; i++) {
        if (cancelled) return;
        const pathSoFar = segments.slice(0, i + 1);
        const node = getNodeAtPath(nodesRef.current, pathSoFar, 0);
        if (!node) return;

        // Expand this node
        setNodes((prev) =>
          updateNodeAtPath(prev, pathSoFar, 0, (n) => ({
            ...n,
            isExpanded: true,
          })),
        );

        // If children not loaded, load them
        if (node.children === null && i < segments.length - 1) {
          const isRootNode = pathSoFar.length === 1 && pathSoFar[0] === root;
          const fullPath = isRootNode
            ? rootPath
            : `${rootPath}/${pathSoFar.slice(1).join("/")}`;

          try {
            const { list } = await loadDirectory(fullPath);
            if (cancelled) return;
            setNodes((prev) =>
              updateNodeAtPath(prev, pathSoFar, 0, (n) => ({
                ...n,
                children: buildDirectoryNodes(list),
                isLoading: false,
                isExpanded: true,
              })),
            );
            // Allow state to settle so nodesRef picks up new children
            await new Promise((r) => setTimeout(r, 0));
          } catch {
            return;
          }
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [currentPath, rootPath, root, loadDirectory]);

  const handleNodeClick = (path: string[]) => {
    const pathStr = path.join("/");
    setActivePath(pathStr);
    const targetNode = getNodeAtPath(nodes, path, 0);
    if (!targetNode) return;

    const isRootNode = path.length === 1 && path[0] === root;
    const fullPath = isRootNode
      ? rootPath
      : `${rootPath}/${path.slice(1).join("/")}`;

    lastInternalNavRef.current = fullPath;
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
            isActive ? "bg-amber-100 dark:bg-amber-900" : "hover:bg-accent"
          }`}
          style={{ paddingLeft: `${depth * 16 + 8}px` }}
          onClick={() => handleNodeClick(currentPath)}
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
